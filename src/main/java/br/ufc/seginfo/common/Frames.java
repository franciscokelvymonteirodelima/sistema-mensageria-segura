package br.ufc.seginfo.common;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Enquadramento (framing) no TCP.
 *
 * O TCP e um fluxo de bytes e nao separa mensagens. Por isso todo frame vai assim:
 *
 *   [len 4B big-endian][type 1B][payload]
 *
 * onde len = tamanho de (type + payload).
 */
public final class Frames {

    private Frames() {
    }

    /** Um frame ja lido: tipo + conteudo. */
    public record Frame(byte type, byte[] payload) {
    }

    /** Frame invalido (tamanho fora do limite). Quem recebe deve fechar a conexao. */
    public static class FrameException extends IOException {
        public FrameException(String msg) {
            super(msg);
        }
    }

    /**
     * Le um frame completo do stream.
     * - FrameException: tamanho invalido (0, negativo ou maior que MAX_FRAME).
     * - EOFException (subclasse de IOException): a conexao fechou no meio.
     */
    public static Frame read(DataInputStream in) throws IOException {
        int len = in.readInt(); // 4 bytes, big-endian

        // Valida ANTES de alocar memoria, senao um len gigante estoura o servidor
        if (len < 1 || len > Types.MAX_FRAME) {
            throw new FrameException("tamanho de frame invalido: " + len);
        }

        byte[] corpo = new byte[len];
        in.readFully(corpo); // espera chegar tudo (read() comum pode devolver menos)

        byte type = corpo[0];
        byte[] payload = Arrays.copyOfRange(corpo, 1, len);
        return new Frame(type, payload);
    }

    /**
     * Escreve um frame. Monta tudo num array e escreve de uma vez so,
     * para dois frames nunca se misturarem no stream.
     * (A sincronizacao entre threads fica na Session, nao aqui.)
     */
    public static void write(DataOutputStream out, byte type, byte[] payload) throws IOException {
        int len = 1 + payload.length;
        if (len > Types.MAX_FRAME) {
            throw new FrameException("frame grande demais para enviar: " + len);
        }

        ByteBuffer buf = ByteBuffer.allocate(4 + len); // ByteBuffer ja e big-endian
        buf.putInt(len);
        buf.put(type);
        buf.put(payload);

        out.write(buf.array());
        out.flush();
    }

    /**
     * Escreve so um campo len cru, sem frame de verdade.
     * Usado apenas pelo comando /badframe, para testar o "framing invalido".
     */
    public static void writeRawLength(DataOutputStream out, int len) throws IOException {
        out.writeInt(len);
        out.flush();
    }
}
 
