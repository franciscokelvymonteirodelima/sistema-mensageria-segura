package br.ufc.seginfo.client;

import br.ufc.seginfo.common.Certs;
import br.ufc.seginfo.common.CryptoUtil;
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
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

/**
 * Liga o cliente. Nesta etapa: conecta, faz o handshake e fica conectado.
 *
 * Uso: ClientMain [host] [porta] [caminho do server.crt]
 * Padroes: localhost, 5000, certs/server.crt
 *
 * Comandos (por enquanto): /badframe (testa framing invalido) e /sair.
 * Os comandos de chat (/send, /tamper, /replay) entram nas proximas etapas.
 */
public class ClientMain {

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
            KeyPair par = CryptoUtil.gerarParX25519();
            byte[] pkC = CryptoUtil.chavePublicaRaw(par.getPublic());
            Log.info("meu client_id=" + Ids.paraUuid(clientId) + " pk=" + Log.fingerprint(pkC));

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

            // thread que le o que o servidor manda
            Thread leitor = new Thread(() -> lerDoServidor(in, r.ultimoSeqServidor(), socket));
            leitor.setDaemon(true);
            leitor.start();

            // teclado
            System.out.println("Comandos: /badframe  /sair");
            BufferedReader teclado = new BufferedReader(new InputStreamReader(System.in));
            String linha;
            while ((linha = teclado.readLine()) != null) {
                linha = linha.strip();
                if (linha.equals("/sair")) {
                    break;
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

    /** Le frames do servidor. Mensagens administrativas so valem se o seq for maior que o ultimo. */
    private static void lerDoServidor(DataInputStream in, long ultimoSeq, Socket socket) {
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
                Log.info(String.format("recebido frame 0x%02x (%d bytes)", f.type(), f.payload().length));
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
}