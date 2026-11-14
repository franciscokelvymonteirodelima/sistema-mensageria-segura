// & (Get-ChildItem "$env:USERPROFILE\.jdks" -Recurse -Filter java.exe | Select-Object -First 1).FullName -cp target/classes br.ufc.seginfo.client.ClientMain

// cole esse comando la no terminal para poder criar multiplos clientes asim será mais facil ...

package br.ufc.seginfo.client;

import br.ufc.seginfo.common.Certs;
import br.ufc.seginfo.common.CryptoUtil;
import br.ufc.seginfo.common.E2EFrame;
import br.ufc.seginfo.common.Frames;
import br.ufc.seginfo.common.Ids;
import br.ufc.seginfo.common.Log;
import br.ufc.seginfo.common.Types;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

/**
 * Liga o cliente: conecta, faz o handshake, acompanha quem entra e sai e fica conectado.
 *
 * Uso: ClientMain [host] [porta] [caminho do server.crt]
 * Padroes: localhost, 5000, certs/server.crt
 *
 * Comandos de uso:   /peers, /send <inicio do id> <texto> e /sair.
 * Comandos de TESTE de seguranca (para a demonstracao):
 *   /tamper <inicio do id> <texto>  manda uma mensagem com 1 bit adulterado (o destinatario deve rejeitar)
 *   /replay                         reenvia o ultimo frame valido (o destinatario deve rejeitar)
 *   /badframe                       manda um tamanho de frame absurdo (o servidor deve desconectar)
 */
public class ClientMain {

    // Dados desta execucao, usados tambem pela thread que le o servidor
    private static byte[] meuClientId;
    private static PrivateKey minhaChavePrivada;
    private static byte[] meuSalt;

    // Ultimo frame E2E VALIDO enviado com /send (usado pelo /replay). So a thread do teclado mexe nele.
    private static byte[] ultimoFrameEnviado;

    public static void main(String[] args) {
        Log.setTag("CLIENT");

        String host = args.length > 0 ? args[0] : "localhost";
        int porta = args.length > 1 ? Integer.parseInt(args[1]) : Types.PORT;
        Path arquivoCrt = Path.of(args.length > 2 ? args[2] : "certs/server.crt");

        try {
            // certificado PINADO: a unica coisa em que confiamos sobre o servidor
            X509Certificate pinado = Certs.carregarCertificado(arquivoCrt);
            pinado.checkValidity();

            // identidade e par de chaves efemero desta execucao
            byte[] clientId = Ids.novoClientId();
            UUID meuId = Ids.paraUuid(clientId);
            KeyPair par = CryptoUtil.gerarParX25519();
            byte[] pkC = CryptoUtil.chavePublicaRaw(par.getPublic());
            String meuFingerprint = Log.fingerprint(pkC);
            Log.info("meu client_id=" + meuId + " pk=" + meuFingerprint);

            Socket socket = new Socket(host, porta);
            socket.setSoTimeout(Types.HANDSHAKE_TIMEOUT_MS);
            DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            Handshake.Resultado r;
            try {
                r = Handshake.executar(in, out, clientId, pkC, pinado);
            } catch (Handshake.HandshakeException e) {
                Log.error("handshake recusado: " + e.getMessage());
                socket.close();
                System.exit(1);
                return;
            }
            socket.setSoTimeout(0);
            Log.info("handshake concluido: servidor autenticado e cliente registrado");

            meuClientId = clientId;
            minhaChavePrivada = par.getPrivate();
            meuSalt = r.salt(); // o salt que o servidor me deu: entra no HKDF quando eu sou o "A" do par

            // lista de contatos, atualizada pela thread que le o servidor
            PeerTable tabela = new PeerTable();

            Thread leitor = new Thread(
                    () -> lerDoServidor(in, r.ultimoSeqServidor(), socket, meuId, tabela));
            leitor.setDaemon(true);
            leitor.start();

            // teclado
            System.out.println("Comandos: /peers  /send <id> <texto>  /sair");
            System.out.println("Testes:   /tamper <id> <texto>  /replay  /badframe");
            BufferedReader teclado = new BufferedReader(new InputStreamReader(System.in));
            String linha;
            while ((linha = teclado.readLine()) != null) {
                linha = linha.strip();
                if (linha.equals("/sair")) {
                    break;
                } else if (linha.equals("/peers")) {
                    mostrarPeers(meuId, meuFingerprint, tabela);
                } else if (linha.startsWith("/send ")) {
                    enviar(linha.substring(6).strip(), tabela, out, false);
                } else if (linha.startsWith("/tamper ")) {
                    enviar(linha.substring(8).strip(), tabela, out, true);
                } else if (linha.equals("/replay")) {
                    reenviarUltimo(out);
                } else if (linha.equals("/badframe")) {
                    Log.warn("enviando frame com tamanho invalido de proposito");
                    Frames.writeRawLength(out, Integer.MAX_VALUE);
                } else if (!linha.isEmpty()) {
                    System.out.println("comando desconhecido: " + linha);
                }
            }
            socket.close();

        } catch (Exception e) {
            Log.error("falha no cliente: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            System.exit(1);
        }
    }

    /** /peers: mostra quem esta online. Compare o fingerprint com o que o outro ve no terminal dele. */
    private static void mostrarPeers(UUID meuId, String meuFingerprint, PeerTable tabela) {
        System.out.println("voce:  " + meuId + "  pk=" + meuFingerprint);
        List<PeerTable.PeerInfo> lista = tabela.listar();
        if (lista.isEmpty()) {
            System.out.println("nenhum outro cliente online");
            return;
        }
        System.out.println(lista.size() + " peer(s) online:");
        for (PeerTable.PeerInfo p : lista) {
            System.out.println("  " + p.uuid() + "  pk=" + Log.fingerprint(p.chavePublica()));
        }
    }

    /**
     * Le frames do servidor. Mensagens administrativas so valem se o seq for maior que o ultimo
     * (anti-replay); depois disso, cada tipo e tratado.
     */
    private static void lerDoServidor(DataInputStream in, long ultimoSeq, Socket socket,
                                      UUID meuId, PeerTable tabela) {
        try {
            while (true) {
                Frames.Frame f = Frames.read(in);
                boolean administrativo = f.type() >= Types.REGISTERED && f.type() <= Types.ERROR;
                if (administrativo) {
                    if (f.payload().length < Types.SEQ_LEN) {
                        Log.warn("mensagem administrativa curta demais, descartada");
                        continue;
                    }
                    long seq = ByteBuffer.wrap(f.payload()).getLong();
                    if (seq <= ultimoSeq) {
                        Log.warn("mensagem administrativa repetida ou antiga (replay?), descartada");
                        continue;
                    }
                    ultimoSeq = seq;
                }

                switch (f.type()) {
                    case Types.PEER_INFO -> tratarPeerInfo(f.payload(), meuId, tabela);
                    case Types.PEER_LEFT -> tratarPeerLeft(f.payload(), tabela);
                    case Types.E2E -> tratarE2E(f.payload(), tabela);
                    case Types.ERROR -> Log.warn("erro do servidor: " + Handshake.descreverErro(f.payload()));
                    default -> Log.info(String.format("recebido frame 0x%02x (%d bytes) - ainda nao tratado",
                            f.type(), f.payload().length));
                }
            }
        } catch (EOFException e) {
            Log.info("o servidor encerrou a conexao");
        } catch (IOException e) {
            if (!socket.isClosed()) {
                Log.warn("conexao encerrada: " + e.getMessage());
            }
        }
        System.exit(0);
    }

    /** Um peer entrou (ou reconectou com chave nova): guarda na tabela. */
    private static void tratarPeerInfo(byte[] payload, UUID meuId, PeerTable tabela) {
        PeerTable.PeerInfo info = PeerTable.parsearPeerInfo(payload);
        if (info == null) {
            Log.warn("PEER_INFO malformado, descartado");
            return;
        }
        UUID id = info.uuid();
        if (id.equals(meuId)) {
            Log.warn("PEER_INFO com o meu proprio id, ignorado");
            return;
        }
        try {
            CryptoUtil.chavePublicaDeRaw(info.chavePublica()); // so confere se e uma chave X25519 valida
        } catch (GeneralSecurityException e) {
            Log.warn("PEER_INFO com chave publica invalida, descartado");
            return;
        }
        boolean jaConhecia = tabela.buscar(id) != null;

        // ECDH + HKDF: deriva as chaves AES deste contato (se ele reconectou, substitui o Peer antigo)
        Peer peer;
        try {
            peer = Peer.criar(meuClientId, minhaChavePrivada, info, meuSalt);
        } catch (GeneralSecurityException e) {
            tabela.remover(id);
            Log.warn("nao foi possivel derivar as chaves com " + id + ", contato ignorado");
            return;
        }
        tabela.adicionar(info);
        tabela.adicionarPeer(peer);
        Log.info((jaConhecia ? "peer reconectou (chave nova): " : "peer entrou: ")
                + "id=" + id + " pk=" + Log.fingerprint(info.chavePublica())
                + " (online: " + tabela.total() + ")");
    }

    /**
     * /send <inicio do id> <texto>: cifra para o contato e manda ao servidor, que so repassa.
     * /tamper (adulterar = true): igual, mas inverte 1 bit do texto cifrado antes de enviar,
     * como faria um atacante no caminho. E so para demonstrar que o destinatario rejeita.
     */
    private static void enviar(String args, PeerTable tabela, DataOutputStream out, boolean adulterar)
            throws IOException {
        String comando = adulterar ? "/tamper" : "/send";
        int espaco = args.indexOf(' ');
        if (espaco < 0) {
            System.out.println("uso: " + comando + " <inicio do id> <texto>");
            return;
        }
        String prefixo = args.substring(0, espaco);
        String texto = args.substring(espaco + 1).strip();
        if (prefixo.length() < 4 || texto.isEmpty()) {
            System.out.println("uso: " + comando + " <inicio do id (minimo 4 caracteres)> <texto>");
            return;
        }
        byte[] bytes = texto.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > Types.MAX_PLAINTEXT) {
            System.out.println("mensagem grande demais: " + bytes.length + " bytes (maximo "
                    + Types.MAX_PLAINTEXT + ")");
            return;
        }
        List<Peer> achados = tabela.buscarPorPrefixo(prefixo);
        if (achados.isEmpty()) {
            System.out.println("nenhum contato online com id comecando por " + prefixo + " (veja /peers)");
            return;
        }
        if (achados.size() > 1) {
            System.out.println("id ambiguo: digite mais caracteres");
            return;
        }
        Peer peer = achados.get(0);
        byte[] payload = peer.cifrar(bytes);
        if (adulterar) {
            // O primeiro byte depois do cabecalho de 52 bytes e o inicio do texto cifrado
            payload[Types.E2E_HEADER_LEN] ^= 0x01;
            Log.warn("adulterando de proposito: 1 bit do texto cifrado foi invertido antes de enviar");
        } else {
            ultimoFrameEnviado = payload.clone(); // so frames validos podem ser reenviados pelo /replay
        }
        Frames.write(out, Types.E2E, payload);
        System.out.println((adulterar ? "enviado (ADULTERADO) para " : "enviado para ")
                + peer.uuid().toString().substring(0, 8));
    }

    /** /replay: reenvia, byte a byte, o ultimo frame valido. O destinatario ja o aceitou uma vez. */
    private static void reenviarUltimo(DataOutputStream out) throws IOException {
        if (ultimoFrameEnviado == null) {
            System.out.println("nada para reenviar: use /send antes");
            return;
        }
        Log.warn("reenviando de proposito o ultimo frame enviado (replay)");
        Frames.write(out, Types.E2E, ultimoFrameEnviado);
        System.out.println("frame reenviado");
    }

    /** Chegou uma mensagem cifrada: confere o endereco, decifra e valida tag e contador. */
    private static void tratarE2E(byte[] payload, PeerTable tabela) {
        E2EFrame frame = E2EFrame.parsear(payload);
        if (frame == null) {
            Log.warn("frame E2E com tamanho invalido, descartado");
            return;
        }
        if (!Arrays.equals(frame.recipientId(), meuClientId)) {
            Log.warn("frame E2E que nao e para mim, descartado");
            return;
        }
        UUID remetente = Ids.paraUuid(frame.senderId());
        Peer peer = tabela.buscarPeer(remetente);
        if (peer == null) {
            Log.warn("frame E2E de remetente desconhecido: " + remetente);
            return;
        }
        Peer.Resultado r = peer.decifrar(frame);
        if (!r.ok()) {
            // so o motivo vai para o log, nunca o conteudo
            Log.warn("mensagem de " + remetente + " rejeitada: " + r.rejeicao());
            return;
        }
        // o texto vem de outra pessoa: troca caracteres de controle para ninguem mexer no seu terminal
        String texto = new String(r.texto(), StandardCharsets.UTF_8).replaceAll("\\p{Cntrl}", "?");
        System.out.println("[" + remetente.toString().substring(0, 8) + "] " + texto);
    }

    /** Um peer saiu: tira da tabela. */
    private static void tratarPeerLeft(byte[] payload, PeerTable tabela) {
        UUID id = PeerTable.parsearPeerLeft(payload);
        if (id == null) {
            Log.warn("PEER_LEFT malformado, descartado");
            return;
        }
        if (tabela.remover(id)) {
            Log.info("peer saiu: id=" + id + " (online: " + tabela.total() + ")");
        } else {
            Log.warn("PEER_LEFT de peer desconhecido: " + id);
        }
    }
}