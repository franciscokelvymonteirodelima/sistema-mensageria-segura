package br.ufc.seginfo.server;

import br.ufc.seginfo.common.CryptoUtil;
import br.ufc.seginfo.common.Frames;
import br.ufc.seginfo.common.Ids;

import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.UUID;

/**
 * A "ficha" de um cliente conectado ao servidor.
 *
 * Varias threads podem escrever no mesmo cliente (por exemplo, o roteador encaminhando
 * mensagens de varios remetentes), entao toda escrita e synchronized: dois frames
 * nunca se misturam no mesmo socket.
 */
public final class Session {

    private final Socket socket;
    private final DataOutputStream out;
    private final byte[] clientId;
    private final UUID uuid;
    private final byte[] chavePublica;  // pk_C (32 bytes raw)
    private final byte[] salt;          // salt_srv (16 bytes), gerado pelo servidor

    // proximo seq das mensagens ADMINISTRATIVAS que o servidor envia a este cliente
    private long seqSend = 0;

    // Existe na tabela do enunciado, mas o servidor NAO valida o seq dos frames E2E:
    // quem faz o anti-replay e o destinatario.
    private long seqRecv = -1;

    public Session(Socket socket, DataOutputStream out, byte[] clientId, byte[] chavePublica, byte[] salt) {
        this.socket = socket;
        this.out = out;
        this.clientId = clientId;
        this.uuid = Ids.paraUuid(clientId);
        this.chavePublica = chavePublica;
        this.salt = salt;
    }

    public byte[] clientId() {
        return clientId;
    }

    public UUID uuid() {
        return uuid;
    }

    public byte[] chavePublica() {
        return chavePublica;
    }

    public byte[] salt() {
        return salt;
    }

    public synchronized long seqRecv() {
        return seqRecv;
    }

    /** Envia um frame como esta (SERVER_HELLO, ou E2E encaminhado sem alteracao). */
    public synchronized void enviar(byte tipo, byte[] payload) throws IOException {
        Frames.write(out, tipo, payload);
    }

    /**
     * Envia uma mensagem administrativa: payload = seq(8) | corpo.
     * O seq cresce a cada mensagem e serve para ordenacao e anti-replay no cliente.
     * (Nao tem criptografia nem MAC: o enunciado nao define chave entre servidor e cliente.)
     */
    public synchronized void enviarAdmin(byte tipo, byte[]... corpo) throws IOException {
        byte[] seq = ByteBuffer.allocate(8).putLong(seqSend).array();
        Frames.write(out, tipo, CryptoUtil.concat(seq, CryptoUtil.concat(corpo)));
        seqSend++; // so avanca depois de escrever com sucesso
    }

    /** Fecha o socket sem reclamar de erro. */
    public void fechar() {
        try {
            socket.close();
        } catch (IOException ignorado) {
            // ja estava fechado
        }
    }
}