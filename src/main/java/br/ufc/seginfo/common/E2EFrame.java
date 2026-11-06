package br.ufc.seginfo.common;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * O "formulario" da mensagem cifrada de ponta a ponta (payload do frame tipo E2E):
 *
 *   nonce(12) | sender_id(16) | recipient_id(16) | seq_no(8) | texto cifrado + tag(16)
 *   offsets:   0..11   12..27       28..43          44..51      52..
 *
 * O AAD (dados autenticados pelo AES-GCM, mas nao cifrados) e:
 *   sender_id | recipient_id | seq_no   (40 bytes)
 * Se alguem trocar o destinatario ou o contador no caminho, a tag do GCM falha.
 */
public record E2EFrame(byte[] nonce, byte[] senderId, byte[] recipientId, long seqNo, byte[] cifrado) {

    private static final int OFFSET_SENDER = Types.NONCE_LEN;                          // 12
    private static final int OFFSET_RECIPIENT = OFFSET_SENDER + Types.CLIENT_ID_LEN;   // 28

    /** AAD de 40 bytes: sender_id | recipient_id | seq_no (big-endian). */
    public static byte[] aad(byte[] senderId, byte[] recipientId, long seqNo) {
        return ByteBuffer.allocate(2 * Types.CLIENT_ID_LEN + Types.SEQ_LEN)
                .put(senderId)
                .put(recipientId)
                .putLong(seqNo)
                .array();
    }

    /** Transforma o frame nos bytes que vao no payload. */
    public byte[] serializar() {
        return ByteBuffer.allocate(Types.E2E_HEADER_LEN + cifrado.length)
                .put(nonce)
                .put(senderId)
                .put(recipientId)
                .putLong(seqNo)
                .put(cifrado)
                .array();
    }

    /** O payload tem um tamanho possivel? (cabecalho + tag, no minimo; 4096 de texto, no maximo) */
    public static boolean tamanhoValido(int tamanho) {
        return tamanho >= Types.E2E_MIN_PAYLOAD && tamanho <= Types.E2E_MAX_PAYLOAD;
    }

    /** Le os bytes do payload. Devolve null se o tamanho for impossivel. */
    public static E2EFrame parsear(byte[] payload) {
        if (!tamanhoValido(payload.length)) {
            return null;
        }
        ByteBuffer bb = ByteBuffer.wrap(payload);
        byte[] nonce = new byte[Types.NONCE_LEN];
        byte[] sender = new byte[Types.CLIENT_ID_LEN];
        byte[] recipient = new byte[Types.CLIENT_ID_LEN];
        bb.get(nonce);
        bb.get(sender);
        bb.get(recipient);
        long seq = bb.getLong();
        byte[] cifrado = new byte[bb.remaining()];
        bb.get(cifrado);
        return new E2EFrame(nonce, sender, recipient, seq, cifrado);
    }

    // O servidor so precisa destes dois campos para rotear; ele nunca monta o frame inteiro.

    public static byte[] senderIdDe(byte[] payload) {
        return Arrays.copyOfRange(payload, OFFSET_SENDER, OFFSET_SENDER + Types.CLIENT_ID_LEN);
    }

    public static byte[] recipientIdDe(byte[] payload) {
        return Arrays.copyOfRange(payload, OFFSET_RECIPIENT, OFFSET_RECIPIENT + Types.CLIENT_ID_LEN);
    }
}