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
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.UUID;

/**
 * Liga o cliente: conecta, faz o handshake, acompanha quem entra e sai e fica conectado.
 *
 * Uso: ClientMain [host] [porta] [caminho do server.crt]
 * Padroes: localhost, 5000, certs/server.crt
 *
 * Comandos (por enquanto): /peers, /badframe e /sair.
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

            // lista de contatos, atualizada pela thread que le o servidor
            PeerTable tabela = new PeerTable();

            Thread leitor = new Thread(
                    () -> lerDoServidor(in, r.ultimoSeqServidor(), socket, meuId, tabela));
            leitor.setDaemon(true);
            leitor.start();

            // teclado
            System.out.println("Comandos: /peers  /badframe  /sair");
            BufferedReader teclado = new BufferedReader(new InputStreamReader(System.in));
            String linha;
            while ((linha = teclado.readLine()) != null) {
                linha = linha.strip();
                if (linha.equals("/sair")) {
                    break;
                } else if (linha.equals("/peers")) {
                    mostrarPeers(meuId, meuFingerprint, tabela);
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
        tabela.adicionar(info);
        Log.info((jaConhecia ? "peer reconectou (chave nova): " : "peer entrou: ")
                + "id=" + id + " pk=" + Log.fingerprint(info.chavePublica())
                + " (online: " + tabela.total() + ")");
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