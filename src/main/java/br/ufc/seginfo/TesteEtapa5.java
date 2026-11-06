package br.ufc.seginfo;

import br.ufc.seginfo.client.Handshake;
import br.ufc.seginfo.client.Peer;
import br.ufc.seginfo.client.PeerTable;
import br.ufc.seginfo.common.Certs;
import br.ufc.seginfo.common.Certs.Identidade;
import br.ufc.seginfo.common.CryptoUtil;
import br.ufc.seginfo.common.E2EFrame;
import br.ufc.seginfo.common.Frames;
import br.ufc.seginfo.common.Ids;
import br.ufc.seginfo.common.Log;
import br.ufc.seginfo.common.Types;
import br.ufc.seginfo.server.Server;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Teste da Etapa 5.
 *   Parte 1: sem rede. Dois Peer trocam mensagens; atacamos o frame de todo jeito.
 *   Parte 2: com servidor e clientes de verdade, por socket.
 * Pode apagar quando a etapa estiver aprovada.
 */
public class TesteEtapa5 {

    static int falhas = 0;
    static final List<Socket> abertos = Collections.synchronizedList(new ArrayList<>());

    static void check(String nome, boolean ok) {
        System.out.println((ok ? "[OK]     " : "[FALHOU] ") + nome);
        if (!ok) {
            falhas++;
        }
    }

    static byte[] bytes(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    static boolean contem(byte[] palha, byte[] agulha) {
        for (int i = 0; i + agulha.length <= palha.length; i++) {
            if (Arrays.equals(Arrays.copyOfRange(palha, i, i + agulha.length), agulha)) {
                return true;
            }
        }
        return false;
    }

    // ---------- certificado temporario via keytool ----------

    static Identidade gerarIdentidade(Path dir, String nome) throws Exception {
        Path p12 = dir.resolve(nome + ".p12");
        String keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
        executar(keytool, "-genkeypair", "-alias", "server", "-keyalg", "RSA", "-keysize", "2048",
                "-validity", "30", "-dname", "CN=" + nome, "-keystore", p12.toString(),
                "-storetype", "PKCS12", "-storepass", "changeit", "-keypass", "changeit");
        executar(keytool, "-exportcert", "-alias", "server", "-keystore", p12.toString(),
                "-storepass", "changeit", "-rfc", "-file", dir.resolve(nome + ".crt").toString());
        return Certs.carregarIdentidade(p12, "changeit".toCharArray());
    }

    static void executar(String... cmd) throws Exception {
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        String saida = new String(p.getInputStream().readAllBytes());
        if (p.waitFor() != 0) {
            throw new IllegalStateException("comando falhou: " + String.join(" ", cmd) + "\n" + saida);
        }
    }

    // =====================================================================
    // Parte 1: sem rede
    // =====================================================================

    /** Um participante: id, par X25519 e o salt que o servidor lhe daria. */
    record Par(byte[] id, KeyPair chaves, byte[] salt) {
        static Par novo() {
            return new Par(Ids.novoClientId(), CryptoUtil.gerarParX25519(), CryptoUtil.aleatorio(Types.SALT_LEN));
        }

        PeerTable.PeerInfo info() {
            return new PeerTable.PeerInfo(id, CryptoUtil.chavePublicaRaw(chaves.getPublic()), salt);
        }

        /** O Peer que EU uso para falar com 'outro'. */
        Peer peerCom(Par outro) throws Exception {
            return Peer.criar(id, chaves.getPrivate(), outro.info(), salt);
        }
    }

    static Peer.Resultado entregar(Peer receptor, byte[] payload) {
        return receptor.decifrar(E2EFrame.parsear(payload));
    }

    static boolean motivo(Peer.Resultado r, Peer.Rejeicao esperado) {
        return !r.ok() && r.rejeicao() == esperado;
    }

    static void parte1() throws Exception {
        System.out.println("=== Parte 1: Peer, sem rede ===");

        Par a = Par.novo();
        Par b = Par.novo();
        Par c = Par.novo();
        Peer ab = a.peerCom(b); // como A fala com B
        Peer ba = b.peerCom(a); // como B fala com A

        byte[] msg = bytes("ola, B! acentuação ok");
        byte[] f0 = ab.cifrar(msg);
        Peer.Resultado r = entregar(ba, f0);
        check("A cifra, B decifra e le o texto original", r.ok() && Arrays.equals(r.texto(), msg));

        byte[] resp = bytes("oi, A!");
        r = entregar(ab, ba.cifrar(resp));
        check("B responde, A decifra (direcao contraria)", r.ok() && Arrays.equals(r.texto(), resp));

        boolean todos = true;
        for (int i = 0; i < 20; i++) {
            Par x = Par.novo();
            Par y = Par.novo();
            Peer xy = x.peerCom(y);
            Peer yx = y.peerCom(x);
            Peer.Resultado r1 = entregar(yx, xy.cifrar(msg));
            Peer.Resultado r2 = entregar(xy, yx.cifrar(msg));
            todos &= r1.ok() && r2.ok() && Arrays.equals(r1.texto(), msg) && Arrays.equals(r2.texto(), msg);
        }
        check("funciona nos dois sentidos com 20 pares aleatorios (quem e o 'A' varia)", todos);

        check("o texto nao aparece no frame cifrado", !contem(f0, bytes("ola, B!")));
        check("tamanho do frame = 52 (cabecalho) + texto + 16 (tag)",
                f0.length == Types.E2E_HEADER_LEN + msg.length + Types.TAG_LEN);

        // contadores e nonces
        byte[] f1 = ab.cifrar(msg);                  // mesmo texto de novo
        byte[] f2 = ab.cifrar(bytes("terceira"));
        E2EFrame p0 = E2EFrame.parsear(f0);
        E2EFrame p1 = E2EFrame.parsear(f1);
        E2EFrame p2 = E2EFrame.parsear(f2);
        check("seq_no cresce: 0, 1, 2", p0.seqNo() == 0 && p1.seqNo() == 1 && p2.seqNo() == 2);
        check("nonces diferentes a cada mensagem",
                !Arrays.equals(p0.nonce(), p1.nonce()) && !Arrays.equals(p1.nonce(), p2.nonce()));
        check("mesmo texto, 2 mensagens: ciphertexts diferentes", !Arrays.equals(p0.cifrado(), p1.cifrado()));
        check("o IV_base e o mesmo durante a conversa (so o seq_no muda no nonce)",
                Arrays.equals(Arrays.copyOf(p0.nonce(), 4), Arrays.copyOf(p1.nonce(), 4)));

        // BITFLIP: cada bit de cada byte do frame f1 (o ba ja aceitou f0, entao tem estado)
        boolean todasRejeitadas = true;
        int tentativas = 0;
        for (int i = 0; i < f1.length; i++) {
            for (int bit = 0; bit < 8; bit++) {
                byte[] adulterado = f1.clone();
                adulterado[i] ^= (byte) (1 << bit);
                tentativas++;
                if (entregar(ba, adulterado).ok()) {
                    todasRejeitadas = false;
                }
            }
        }
        check("bitflip em cada um dos " + tentativas + " bits do frame: TODOS rejeitados", todasRejeitadas);

        // motivos especificos (frame novo, ainda nao entregue)
        byte[] f3 = ab.cifrar(bytes("para testar motivos"));
        byte[] x = f3.clone();
        x[Types.NONCE_LEN + Types.CLIENT_ID_LEN] ^= 1;                    // 1 bit do recipient_id
        check("recipient_id alterado => ENDERECO_INVALIDO", motivo(entregar(ba, x), Peer.Rejeicao.ENDERECO_INVALIDO));
        x = f3.clone();
        x[Types.E2E_HEADER_LEN - 1] ^= 1;                                  // ultimo byte do seq_no do cabecalho
        check("seq_no do cabecalho alterado => NONCE_INCOERENTE", motivo(entregar(ba, x), Peer.Rejeicao.NONCE_INCOERENTE));
        x = f3.clone();
        x[Types.E2E_HEADER_LEN] ^= 1;                                      // 1 bit do texto cifrado
        check("texto cifrado alterado => TAG_INVALIDA", motivo(entregar(ba, x), Peer.Rejeicao.TAG_INVALIDA));
        x = f3.clone();
        x[f3.length - 1] ^= 1;                                             // 1 bit da propria tag
        check("tag alterada => TAG_INVALIDA", motivo(entregar(ba, x), Peer.Rejeicao.TAG_INVALIDA));

        // o estado nao foi corrompido pelos ataques
        check("depois de todos os ataques, a mensagem verdadeira (seq 1) ainda e aceita",
                entregar(ba, f1).ok());

        // REPLAY e ordem
        check("replay do mesmo frame => REPLAY", motivo(entregar(ba, f1), Peer.Rejeicao.REPLAY));
        check("replay do frame inicial (seq 0) => REPLAY", motivo(entregar(ba, f0), Peer.Rejeicao.REPLAY));
        check("seq maior que o ultimo e aceito (seq 2)", entregar(ba, f2).ok());
        check("seq 3 aceito, depois reenviar o 2 => REPLAY",
                entregar(ba, f3).ok() && motivo(entregar(ba, f2), Peer.Rejeicao.REPLAY));
        check("ultimo seq aceito por B = 3", ba.ultimoSeqAceito() == 3);

        // salto de contador (mensagens perdidas) e permitido
        ab.cifrar(bytes("perdida 1"));
        ab.cifrar(bytes("perdida 2"));
        check("pular seq_no (mensagens perdidas no caminho) e aceito",
                entregar(ba, ab.cifrar(bytes("depois do salto"))).ok());

        // IV_base: segunda "instancia" de A com as mesmas chaves, mas outro IV_base
        Peer ab2 = a.peerCom(b);
        ab2.cifrar(bytes("seq 0 do ab2"));
        byte[] deAb2 = ab2.cifrar(bytes("seq 1 do ab2"));
        check("IV_base diferente do fixado => IV_BASE_DIFERENTE", motivo(entregar(ba, deAb2), Peer.Rejeicao.IV_BASE_DIFERENTE));

        // enderecos
        byte[] f4 = ab.cifrar(bytes("so para o B"));
        check("A recebe o proprio frame de volta (reflexao) => rejeitado", !entregar(ab, f4).ok());
        Peer cb = c.peerCom(a);
        check("um terceiro (C) recebendo o frame A->B => ENDERECO_INVALIDO",
                motivo(entregar(cb, f4), Peer.Rejeicao.ENDERECO_INVALIDO));

        // limites
        boolean recusou = false;
        try {
            ab.cifrar(new byte[Types.MAX_PLAINTEXT + 1]);
        } catch (IllegalArgumentException e) {
            recusou = true;
        }
        check("texto de 4097 bytes e recusado ao cifrar", recusou);
        byte[] grande = ab.cifrar(new byte[Types.MAX_PLAINTEXT]);
        check("texto de 4096 bytes: frame = 4164 bytes e e decifrado",
                grande.length == Types.E2E_MAX_PAYLOAD && entregar(ba, grande).ok());
        byte[] vazio = ab.cifrar(new byte[0]);
        check("texto vazio: frame = 68 bytes e e decifrado",
                vazio.length == Types.E2E_MIN_PAYLOAD && entregar(ba, vazio).ok());
        check("frame menor que o minimo nao e nem interpretado", E2EFrame.parsear(new byte[67]) == null);
        check("frame maior que o maximo nao e nem interpretado",
                E2EFrame.parsear(new byte[Types.E2E_MAX_PAYLOAD + 1]) == null);

        // reconexao: B volta com chave e salt novos
        byte[] velhoParaB = ab.cifrar(bytes("mensagem das chaves antigas"));
        Par b2 = new Par(b.id(), CryptoUtil.gerarParX25519(), CryptoUtil.aleatorio(Types.SALT_LEN));
        Peer ab_novo = a.peerCom(b2);
        Peer ba_novo = b2.peerCom(a);
        check("apos reconexao, frame feito com as chaves antigas => TAG_INVALIDA",
                motivo(entregar(ba_novo, velhoParaB), Peer.Rejeicao.TAG_INVALIDA));
        byte[] novo = ab_novo.cifrar(bytes("com as chaves novas"));
        check("apos reconexao, o contador recomeca em 0 e a conversa funciona",
                E2EFrame.parsear(novo).seqNo() == 0 && entregar(ba_novo, novo).ok());
    }

    // =====================================================================
    // Parte 2: servidor de verdade
    // =====================================================================

    record Cliente(byte[] id, PrivateKey sk, Socket socket, DataInputStream in, DataOutputStream out,
                   Handshake.Resultado r, Map<UUID, Peer> peers) {
        UUID uuid() {
            return Ids.paraUuid(id);
        }
    }

    static Cliente conectar(int porta, X509Certificate pinado) throws Exception {
        byte[] id = Ids.novoClientId();
        KeyPair par = CryptoUtil.gerarParX25519();
        byte[] pk = CryptoUtil.chavePublicaRaw(par.getPublic());
        Socket s = new Socket("localhost", porta);
        s.setSoTimeout(5000);
        abertos.add(s);
        DataInputStream in = new DataInputStream(new BufferedInputStream(s.getInputStream()));
        DataOutputStream out = new DataOutputStream(s.getOutputStream());
        Handshake.Resultado r = Handshake.executar(in, out, id, pk, pinado);
        return new Cliente(id, par.getPrivate(), s, in, out, r, new HashMap<>());
    }

    /** Le os PEER_INFO / PEER_LEFT pendentes e monta os Peer, como faz o ClientMain. */
    static void prepararPeers(Cliente c) throws Exception {
        c.socket().setSoTimeout(400);
        try {
            while (true) {
                Frames.Frame f = Frames.read(c.in());
                if (f.type() == Types.PEER_INFO) {
                    PeerTable.PeerInfo info = PeerTable.parsearPeerInfo(f.payload());
                    c.peers().put(info.uuid(), Peer.criar(c.id(), c.sk(), info, c.r().salt()));
                } else if (f.type() == Types.PEER_LEFT) {
                    c.peers().remove(PeerTable.parsearPeerLeft(f.payload()));
                }
            }
        } catch (SocketTimeoutException fim) {
            // nada mais pendente
        }
    }

    /** Proximo frame do tipo pedido (ignora os outros), ou null se nao chegar em 'ms'. */
    static Frames.Frame lerTipo(Cliente c, byte tipo, int ms) throws IOException {
        c.socket().setSoTimeout(ms);
        try {
            while (true) {
                Frames.Frame f = Frames.read(c.in());
                if (f.type() == tipo) {
                    return f;
                }
            }
        } catch (SocketTimeoutException e) {
            return null;
        }
    }

    static void enviar(Cliente de, byte[] payload) throws IOException {
        Frames.write(de.out(), Types.E2E, payload);
    }

    static boolean esperarTotal(Server s, int esperado) throws InterruptedException {
        for (int i = 0; i < 60; i++) {
            if (s.clientesConectados() == esperado) {
                return true;
            }
            Thread.sleep(50);
        }
        return false;
    }

    static boolean erroDoServidor(Frames.Frame f, byte codigo) {
        return f != null && f.payload().length > 0 && f.payload()[f.payload().length - 1] == codigo;
    }

    /** O servidor fecha a conexao? (le ate dar erro de fim de stream) */
    static boolean conexaoFechada(Cliente c) {
        try {
            c.socket().setSoTimeout(2000);
            while (true) {
                Frames.read(c.in());
            }
        } catch (SocketTimeoutException e) {
            return false;
        } catch (IOException e) {
            return true;
        }
    }

    static void parte2() throws Exception {
        System.out.println();
        System.out.println("=== Parte 2: servidor de verdade ===");

        Path tmp = Files.createTempDirectory("tp3-certs");
        Identidade real = gerarIdentidade(tmp, "servidor-real");
        X509Certificate crt = Certs.carregarCertificado(tmp.resolve("servidor-real.crt"));

        Server servidor = new Server(real, 0);
        Thread t = new Thread(servidor::rodar);
        t.setDaemon(true);
        t.start();
        int porta = servidor.porta();

        Cliente a = conectar(porta, crt);
        Cliente b = conectar(porta, crt);
        Cliente c = conectar(porta, crt);
        prepararPeers(a);
        prepararPeers(b);
        prepararPeers(c);
        check("cada cliente derivou chaves com os outros 2", a.peers().size() == 2
                && b.peers().size() == 2 && c.peers().size() == 2);

        Peer ab = a.peers().get(b.uuid()); // A -> B
        Peer ba = b.peers().get(a.uuid()); // B -> A

        // A manda para B
        byte[] f = ab.cifrar(bytes("ola B, aqui e o A"));
        enviar(a, f);
        Frames.Frame recebido = lerTipo(b, Types.E2E, 3000);
        check("B recebeu o frame", recebido != null);
        check("o servidor entregou EXATAMENTE os mesmos bytes (nao abriu nem mexeu)",
                recebido != null && Arrays.equals(recebido.payload(), f));
        check("o texto nao aparece nos bytes que o servidor viu", !contem(f, bytes("ola B")));
        Peer.Resultado r = ba.decifrar(E2EFrame.parsear(recebido.payload()));
        check("B decifra e le: 'ola B, aqui e o A'",
                r.ok() && new String(r.texto(), StandardCharsets.UTF_8).equals("ola B, aqui e o A"));
        check("C (terceiro no servidor) NAO recebe nada", lerTipo(c, Types.E2E, 600) == null);

        // B responde
        enviar(b, ba.cifrar(bytes("oi A, recebi")));
        Frames.Frame resp = lerTipo(a, Types.E2E, 3000);
        r = resp == null ? null : ab.decifrar(E2EFrame.parsear(resp.payload()));
        check("B responde e A decifra", r != null && r.ok()
                && new String(r.texto(), StandardCharsets.UTF_8).equals("oi A, recebi"));

        // mensagem do tamanho maximo atravessa o servidor
        byte[] grande = new byte[Types.MAX_PLAINTEXT];
        Arrays.fill(grande, (byte) 'x');
        enviar(a, ab.cifrar(grande));
        recebido = lerTipo(b, Types.E2E, 3000);
        r = recebido == null ? null : ba.decifrar(E2EFrame.parsear(recebido.payload()));
        check("mensagem de 4096 bytes atravessa o servidor e e decifrada",
                r != null && r.ok() && Arrays.equals(r.texto(), grande));

        // ADULTERACAO no caminho
        byte[] adulterada = ab.cifrar(bytes("esta vai ser alterada"));
        adulterada[Types.E2E_HEADER_LEN + 2] ^= 0x01; // bitflip no texto cifrado
        enviar(a, adulterada);
        recebido = lerTipo(b, Types.E2E, 3000);
        r = recebido == null ? null : ba.decifrar(E2EFrame.parsear(recebido.payload()));
        check("frame adulterado chega, mas B rejeita (TAG_INVALIDA)",
                r != null && motivo(r, Peer.Rejeicao.TAG_INVALIDA));

        // a conversa continua normal
        enviar(a, ab.cifrar(bytes("mensagem normal depois do ataque")));
        recebido = lerTipo(b, Types.E2E, 3000);
        r = recebido == null ? null : ba.decifrar(E2EFrame.parsear(recebido.payload()));
        check("depois do ataque, a proxima mensagem verdadeira e aceita", r != null && r.ok());

        // REPLAY
        enviar(a, f); // o primeiro frame de novo
        recebido = lerTipo(b, Types.E2E, 3000);
        r = recebido == null ? null : ba.decifrar(E2EFrame.parsear(recebido.payload()));
        check("reenvio do primeiro frame (replay): B rejeita (REPLAY)",
                r != null && motivo(r, Peer.Rejeicao.REPLAY));

        // destinatario offline: A continua conectado
        byte[] ninguem = Ids.novoClientId();
        byte[] paraNinguem = new E2EFrame(new byte[Types.NONCE_LEN], a.id(), ninguem, 0, new byte[26]).serializar();
        enviar(a, paraNinguem);
        Frames.Frame erro = lerTipo(a, Types.ERROR, 3000);
        check("destinatario offline: servidor responde ERR_RECIPIENT_OFFLINE",
                erroDoServidor(erro, Types.ERR_RECIPIENT_OFFLINE));
        enviar(a, ab.cifrar(bytes("ainda estou conectado")));
        recebido = lerTipo(b, Types.E2E, 3000);
        r = recebido == null ? null : ba.decifrar(E2EFrame.parsear(recebido.payload()));
        check("...e a conexao de A continua funcionando", r != null && r.ok());

        // framing invalido: pequeno demais
        Cliente d = conectar(porta, crt);
        Frames.write(d.out(), Types.E2E, new byte[10]);
        check("E2E menor que o minimo: servidor responde ERR_BAD_FRAME",
                erroDoServidor(lerTipo(d, Types.ERROR, 3000), Types.ERR_BAD_FRAME));
        check("...e fecha a conexao", conexaoFechada(d));

        // framing invalido: grande demais
        Cliente e = conectar(porta, crt);
        Frames.write(e.out(), Types.E2E, new byte[Types.E2E_MAX_PAYLOAD + 1]);
        check("E2E maior que o maximo: servidor responde ERR_BAD_FRAME",
                erroDoServidor(lerTipo(e, Types.ERROR, 3000), Types.ERR_BAD_FRAME));
        check("...e fecha a conexao", conexaoFechada(e));

        // se passar por outro (sender_id forjado)
        Cliente fraudador = conectar(porta, crt);
        prepararPeers(fraudador);
        byte[] forjado = fraudador.peers().get(b.uuid()).cifrar(bytes("sou o A, confia"));
        System.arraycopy(a.id(), 0, forjado, Types.NONCE_LEN, Types.CLIENT_ID_LEN); // troca o sender_id por A
        enviar(fraudador, forjado);
        check("sender_id forjado: servidor responde ERR_BAD_FRAME",
                erroDoServidor(lerTipo(fraudador, Types.ERROR, 3000), Types.ERR_BAD_FRAME));
        check("...e desconecta o fraudador", conexaoFechada(fraudador));
        check("B nao recebe a mensagem forjada", lerTipo(b, Types.E2E, 600) == null);

        check("no fim, so A, B e C continuam online", esperarTotal(servidor, 3));

        for (Socket s : abertos) {
            s.close();
        }
        servidor.parar();
    }

    public static void main(String[] args) throws Exception {
        Log.setTag("TESTE");
        parte1();
        parte2();

        System.out.println();
        if (falhas == 0) {
            System.out.println("TUDO OK - etapa 5 aprovada.");
        } else {
            System.out.println(falhas + " teste(s) falharam.");
            System.exit(1);
        }
    }
}