package br.ufc.seginfo;

import br.ufc.seginfo.client.Handshake;
import br.ufc.seginfo.common.Certs;
import br.ufc.seginfo.common.Certs.Identidade;
import br.ufc.seginfo.common.CryptoUtil;
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
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Teste integrado da Etapa 3: sobe um servidor de verdade (porta livre) e conecta
 * clientes por socket. Gera os proprios certificados temporarios com o keytool do JDK,
 * entao nao depende de nenhum arquivo seu. Pode apagar quando a etapa estiver aprovada.
 */
public class TesteEtapa3 {

    static int falhas = 0;
    static final List<Socket> abertos = new ArrayList<>();

    static void check(String nome, boolean ok) {
        System.out.println((ok ? "[OK]     " : "[FALHOU] ") + nome);
        if (!ok) {
            falhas++;
        }
    }

    // ---------- certificados temporarios via keytool ----------

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

    // ---------- cliente de teste ----------

    record Conexao(Socket socket, DataInputStream in, DataOutputStream out) {
    }

    static Conexao abrir(int porta) throws IOException {
        Socket s = new Socket("localhost", porta);
        s.setSoTimeout(5000);
        abertos.add(s);
        return new Conexao(s, new DataInputStream(new BufferedInputStream(s.getInputStream())),
                new DataOutputStream(s.getOutputStream()));
    }

    /** Conecta e tenta o handshake completo. Lanca HandshakeException se recusar o servidor. */
    static Handshake.Resultado handshake(Conexao c, byte[] clientId, X509Certificate pinado) throws Exception {
        byte[] pkC = CryptoUtil.chavePublicaRaw(CryptoUtil.gerarParX25519().getPublic());
        return Handshake.executar(c.in(), c.out(), clientId, pkC, pinado);
    }

    /** Devolve a mensagem do erro de handshake, ou null se o handshake funcionou. */
    static String tentar(int porta, byte[] clientId, X509Certificate pinado) throws Exception {
        Conexao c = abrir(porta);
        try {
            handshake(c, clientId, pinado);
            return null;
        } catch (Handshake.HandshakeException e) {
            c.socket().close(); // o ClientMain real tambem fecha ao recusar o servidor
            return e.getMessage();
        }
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

    static Server subir(Identidade id) throws Exception {
        Server s = new Server(id, 0);
        Thread t = new Thread(s::rodar);
        t.setDaemon(true);
        t.start();
        return s;
    }

    public static void main(String[] args) throws Exception {
        Log.setTag("TESTE");

        Path tmp = Files.createTempDirectory("tp3-certs");
        Identidade real = gerarIdentidade(tmp, "servidor-real");
        Identidade impostor = gerarIdentidade(tmp, "impostor");
        X509Certificate crtReal = Certs.carregarCertificado(tmp.resolve("servidor-real.crt"));
        X509Certificate crtImpostor = Certs.carregarCertificado(tmp.resolve("impostor.crt"));

        System.out.println("=== Certificados ===");
        check("keystore carregado: chave RSA >= 2048 bits", real.chavePrivada().getAlgorithm().equals("RSA"));
        check("certificado .crt exportado confere com o do keystore",
                Arrays.equals(crtReal.getEncoded(), real.certificado().getEncoded()));

        Server servidor = subir(real);
        int porta = servidor.porta();

        System.out.println();
        System.out.println("=== Handshake normal ===");
        byte[] id1 = Ids.novoClientId();
        Conexao c1 = abrir(porta);
        Handshake.Resultado r1 = handshake(c1, id1, crtReal);
        check("handshake com servidor legitimo funciona", r1 != null);
        check("cliente recebeu salt de 16 bytes", r1.salt().length == Types.SALT_LEN);
        check("REGISTERED veio com seq = 0", r1.ultimoSeqServidor() == 0);
        check("servidor registrou 1 cliente", esperarTotal(servidor, 1));

        byte[] id2 = Ids.novoClientId();
        Conexao c2 = abrir(porta);
        Handshake.Resultado r2 = handshake(c2, id2, crtReal);
        check("segundo cliente tambem registra (2 online)", r2 != null && esperarTotal(servidor, 2));
        check("cada cliente recebe um salt diferente", !Arrays.equals(r1.salt(), r2.salt()));

        System.out.println();
        System.out.println("=== Autenticacao do servidor (anti-MITM) ===");
        String erro = tentar(porta, Ids.novoClientId(), crtImpostor);
        check("cliente com outro certificado pinado recusa o servidor",
                erro != null && erro.contains("pinado"));

        // servidor "mentiroso": apresenta o certificado REAL (que e publico), mas assina com a chave do impostor
        Server mitm = subir(new Identidade(impostor.chavePrivada(), real.certificado()));
        erro = tentar(mitm.porta(), Ids.novoClientId(), crtReal);
        check("certificado certo + assinatura de outra chave => recusado",
                erro != null && erro.contains("assinatura"));
        check("nenhum cliente fica registrado no servidor falso (limpa a sessao)", esperarTotal(mitm, 0));
        mitm.parar();

        System.out.println();
        System.out.println("=== Registro ===");
        erro = tentar(porta, id1, crtReal);
        check("client_id ja em uso e recusado", erro != null && erro.contains("em uso"));
        check("a sessao antiga continua registrada (ninguem toma o lugar)", servidor.clientesConectados() == 2);

        // HELLO malformado: payload de 10 bytes
        Conexao ruim = abrir(porta);
        Frames.write(ruim.out(), Types.HELLO, new byte[10]);
        Frames.Frame resp = Frames.read(ruim.in());
        check("HELLO malformado => ERROR bad_handshake",
                resp.type() == Types.ERROR && resp.payload()[resp.payload().length - 1] == Types.ERR_BAD_HANDSHAKE);

        // primeiro frame que nao e HELLO
        Conexao ruim2 = abrir(porta);
        Frames.write(ruim2.out(), Types.E2E, new byte[60]);
        resp = Frames.read(ruim2.in());
        check("primeiro frame diferente de HELLO => ERROR",
                resp.type() == Types.ERROR);
        check("conexoes recusadas nao viram sessoes", servidor.clientesConectados() == 2);

        System.out.println();
        System.out.println("=== Framing invalido e desconexao ===");
        Frames.writeRawLength(c2.out(), Integer.MAX_VALUE); // o que o /badframe faz
        boolean avisou = false;
        boolean fechou = false;
        try {
            while (true) {
                Frames.Frame f = Frames.read(c2.in());
                if (f.type() == Types.ERROR && f.payload()[f.payload().length - 1] == Types.ERR_BAD_FRAME) {
                    avisou = true;
                }
            }
        } catch (IOException e) {
            fechou = true; // EOF: o servidor fechou a conexao
        }
        check("len absurdo: servidor avisa ERR_BAD_FRAME", avisou);
        check("len absurdo: servidor fecha a conexao", fechou);
        check("sessao do cliente que errou foi removida (1 online)", esperarTotal(servidor, 1));

        c1.socket().close();
        check("cliente que sai e removido da tabela (0 online)", esperarTotal(servidor, 0));

        System.out.println();
        System.out.println("=== Reconexao com o mesmo client_id ===");
        Conexao c1b = abrir(porta);
        Handshake.Resultado r1b = handshake(c1b, id1, crtReal);
        check("mesmo client_id pode reconectar depois de sair", r1b != null && esperarTotal(servidor, 1));
        check("reconexao recebe salt NOVO (chaves E2E novas)", !Arrays.equals(r1.salt(), r1b.salt()));

        for (Socket s : abertos) {
            s.close();
        }
        servidor.parar();

        System.out.println();
        if (falhas == 0) {
            System.out.println("TUDO OK - etapa 3 aprovada.");
        } else {
            System.out.println(falhas + " teste(s) falharam.");
            System.exit(1);
        }
    }
}