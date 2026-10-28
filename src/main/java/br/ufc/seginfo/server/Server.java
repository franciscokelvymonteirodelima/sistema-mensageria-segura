package br.ufc.seginfo.server;

import br.ufc.seginfo.common.Certs.Identidade;
import br.ufc.seginfo.common.CryptoUtil;
import br.ufc.seginfo.common.Frames;
import br.ufc.seginfo.common.Log;
import br.ufc.seginfo.common.Types;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Servidor: aceita varias conexoes (uma virtual thread por cliente) e faz o handshake:
 *
 *   cliente -> HELLO(client_id, pk_C)
 *   servidor -> SERVER_HELLO(salt, certificado, assinatura RSA-PSS)
 *   servidor -> REGISTERED(seq)
 */
public final class Server {

    private final ServerSocket serverSocket;
    private final Identidade identidade;
    private final byte[] certDer;        // certificado inteiro (vai no SERVER_HELLO)
    private final byte[] pkServerDer;    // chave publica RSA (entra no hash assinado)
    private final Router router = new Router();

    /** Abre a porta ja no construtor (porta 0 = o sistema escolhe uma livre, util nos testes). */
    public Server(Identidade identidade, int porta) throws IOException, GeneralSecurityException {
        this.identidade = identidade;
        this.certDer = identidade.certificado().getEncoded();
        this.pkServerDer = identidade.certificado().getPublicKey().getEncoded();
        this.serverSocket = new ServerSocket(porta);
    }

    public int porta() {
        return serverSocket.getLocalPort();
    }

    public int clientesConectados() {
        return router.total();
    }

    /** Laco principal: bloqueia aceitando conexoes ate o servidor ser fechado. */
    public void rodar() {
        Log.info("servidor ouvindo na porta " + porta());
        while (!serverSocket.isClosed()) {
            try {
                Socket socket = serverSocket.accept();
                Thread.startVirtualThread(() -> atender(socket));
            } catch (IOException e) {
                if (!serverSocket.isClosed()) {
                    Log.error("erro ao aceitar conexao: " + e.getMessage());
                }
            }
        }
    }

    public void parar() {
        try {
            serverSocket.close();
        } catch (IOException ignorado) {
            // ja estava fechado
        }
    }

    // ------------------------------------------------------------------

    private void atender(Socket socket) {
        String quem = String.valueOf(socket.getRemoteSocketAddress());
        Log.info("conexao recebida de " + quem);

        Session sessao = null;
        boolean registrada = false;

        try {
            // sem isso, uma conexao muda ficaria pendurada para sempre
            socket.setSoTimeout(Types.HANDSHAKE_TIMEOUT_MS);
            DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            // 1) HELLO: client_id(16) | pk_C(32)
            Frames.Frame hello = Frames.read(in);
            if (hello.type() != Types.HELLO
                    || hello.payload().length != Types.CLIENT_ID_LEN + Types.PK_LEN) {
                erroSemSessao(out, Types.ERR_BAD_HANDSHAKE);
                Log.warn("handshake invalido de " + quem + " (HELLO malformado)");
                return;
            }
            byte[] clientId = Arrays.copyOfRange(hello.payload(), 0, Types.CLIENT_ID_LEN);
            byte[] pkC = Arrays.copyOfRange(hello.payload(), Types.CLIENT_ID_LEN,
                    Types.CLIENT_ID_LEN + Types.PK_LEN);

            try {
                CryptoUtil.chavePublicaDeRaw(pkC); // so confere se e uma chave X25519 valida
            } catch (GeneralSecurityException e) {
                erroSemSessao(out, Types.ERR_BAD_HANDSHAKE);
                Log.warn("handshake invalido de " + quem + " (chave publica invalida)");
                return;
            }

            sessao = new Session(socket, out, clientId, pkC, CryptoUtil.aleatorio(Types.SALT_LEN));
            quem = "cliente " + sessao.uuid();

            // 2) vaga e client_id livre?
            if (router.cheio()) {
                sessao.enviarAdmin(Types.ERROR, new byte[]{Types.ERR_SERVER_FULL});
                Log.warn("servidor cheio, recusando " + quem);
                return;
            }
            if (!router.registrar(sessao)) {
                // nao derruba a sessao antiga: ninguem toma o lugar de outro so sabendo o id
                sessao.enviarAdmin(Types.ERROR, new byte[]{Types.ERR_ID_IN_USE});
                Log.warn("client_id ja em uso, recusando " + quem);
                return;
            }
            registrada = true;

            // 3) SERVER_HELLO: salt(16) | certLen(2) | cert | sigLen(2) | assinatura
            byte[] h = CryptoUtil.hashHandshake(pkServerDer, pkC, clientId, sessao.salt());
            byte[] assinatura = CryptoUtil.assinarPss(identidade.chavePrivada(), h);

            ByteBuffer bb = ByteBuffer.allocate(
                    Types.SALT_LEN + 2 + certDer.length + 2 + assinatura.length);
            bb.put(sessao.salt())
                    .putShort((short) certDer.length).put(certDer)
                    .putShort((short) assinatura.length).put(assinatura);
            sessao.enviar(Types.SERVER_HELLO, bb.array());

            // 4) REGISTERED (mensagem administrativa, seq = 0)
            sessao.enviarAdmin(Types.REGISTERED);
            Log.info("cliente registrado: id=" + sessao.uuid()
                    + " pk=" + Log.fingerprint(pkC)
                    + " (online: " + router.total() + ")");

            // 4.1) agora que o cliente ja tem o REGISTERED, apresenta ele aos outros (e vice-versa)
            router.anunciarEntrada(sessao);

            socket.setSoTimeout(0); // handshake acabou; agora pode ficar ocioso

            // 5) laco de frames. Nesta etapa so registramos o que chega (roteamento vem depois).
            while (true) {
                Frames.Frame f = Frames.read(in);
                Log.info(String.format("frame 0x%02x (%d bytes) de %s - ainda nao tratado",
                        f.type(), f.payload().length, quem));
            }

        } catch (EOFException e) {
            Log.info(quem + " desconectou");
        } catch (SocketTimeoutException e) {
            Log.warn("timeout no handshake de " + quem);
        } catch (Frames.FrameException e) {
            Log.warn("framing invalido de " + quem + ": " + e.getMessage() + " - encerrando conexao");
            if (sessao != null) {
                try {
                    sessao.enviarAdmin(Types.ERROR, new byte[]{Types.ERR_BAD_FRAME});
                } catch (IOException ignorado) {
                    // melhor esforco: vamos fechar de qualquer jeito
                }
            }
        } catch (IOException e) {
            Log.warn("erro de conexao com " + quem + ": " + e.getMessage());
        } catch (RuntimeException e) {
            Log.error("erro inesperado com " + quem + ": " + e.getClass().getSimpleName());
        } finally {
            if (registrada) {
                router.remover(sessao);
                Log.info("sessao removida: " + quem + " (online: " + router.total() + ")");
            }
            // O socket e fechado AQUI, e nao com try-with-resources: assim ele continua
            // aberto durante os blocos catch (que ainda enviam o ERROR ao cliente).
            try {
                socket.close();
            } catch (IOException ignorado) {
                // ja estava fechado
            }
        }
    }

    /** ERROR para quem ainda nao tem sessao (seq fixo 0, so existe nesta resposta). */
    private static void erroSemSessao(DataOutputStream out, byte codigo) throws IOException {
        byte[] seq = new byte[8];
        Frames.write(out, Types.ERROR, CryptoUtil.concat(seq, new byte[]{codigo}));
    }
}