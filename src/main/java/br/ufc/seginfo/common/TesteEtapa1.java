package br.ufc.seginfo.common;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.UUID;

/**
 * Teste manual da Etapa 1 (Types, Frames, Log). Rode o main e veja se tudo da [OK].
 * Pode apagar este arquivo quando a etapa estiver aprovada.
 */
public class TesteEtapa1 {

    static int falhas = 0;

    static void check(String nome, boolean ok) {
        System.out.println((ok ? "[OK]     " : "[FALHOU] ") + nome);
        if (!ok) {
            falhas++;
        }
    }

    // bytes de um "frame" que so tem o campo len
    static byte[] soLen(int len) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        Frames.writeRawLength(new DataOutputStream(b), len);
        return b.toByteArray();
    }

    // true se read() lancar FrameException (tamanho invalido)
    static boolean rejeita(byte[] dados) {
        try {
            Frames.read(new DataInputStream(new ByteArrayInputStream(dados)));
            return false;
        } catch (Frames.FrameException e) {
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    // true se read() lancar EOFException (conexao fechou no meio do frame)
    static boolean fimDeStream(byte[] dados) {
        try {
            Frames.read(new DataInputStream(new ByteArrayInputStream(dados)));
            return false;
        } catch (EOFException e) {
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] r = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    public static void main(String[] args) throws Exception {
        Log.setTag("TESTE");

        System.out.println("=== Frames ===");

        // 1) dois frames escritos em sequencia e lidos de volta separados
        byte[] p1 = "ola".getBytes(StandardCharsets.UTF_8);
        byte[] p2 = "tudo bem".getBytes(StandardCharsets.UTF_8);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(bos);
        Frames.write(out, Types.HELLO, p1);
        Frames.write(out, Types.E2E, p2);
        byte[] bytes = bos.toByteArray();

        check("tamanho total escrito (4+1+3) + (4+1+8) = 21", bytes.length == 21);
        check("len em big-endian: 00 00 00 04",
                bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 4);

        DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes));
        Frames.Frame f1 = Frames.read(in);
        Frames.Frame f2 = Frames.read(in);
        check("frame 1 voltou igual (tipo e payload)",
                f1.type() == Types.HELLO && Arrays.equals(f1.payload(), p1));
        check("frame 2 voltou igual (tipo e payload)",
                f2.type() == Types.E2E && Arrays.equals(f2.payload(), p2));

        // 2) frame com payload vazio e valido (len = 1)
        ByteArrayOutputStream bv = new ByteArrayOutputStream();
        Frames.write(new DataOutputStream(bv), Types.PEER_LEFT, new byte[0]);
        Frames.Frame fv = Frames.read(new DataInputStream(new ByteArrayInputStream(bv.toByteArray())));
        check("payload vazio funciona", fv.type() == Types.PEER_LEFT && fv.payload().length == 0);

        // 3) framing invalido
        check("len absurdo (Integer.MAX_VALUE) rejeitado", rejeita(soLen(Integer.MAX_VALUE)));
        check("len = MAX_FRAME + 1 rejeitado", rejeita(soLen(Types.MAX_FRAME + 1)));
        check("len = 0 rejeitado", rejeita(soLen(0)));
        check("len negativo rejeitado", rejeita(soLen(-5)));

        // 4) len = MAX_FRAME e aceito (so falta dado, entao da EOF)
        check("len = MAX_FRAME e aceito (sem dados => fim de stream)",
                fimDeStream(soLen(Types.MAX_FRAME)));

        // 5) conexao fecha no meio do frame
        check("stream cortado no meio => EOFException",
                fimDeStream(concat(soLen(100), new byte[10])));

        // 6) escrita grande demais
        boolean recusou = false;
        try {
            Frames.write(new DataOutputStream(new ByteArrayOutputStream()),
                    Types.E2E, new byte[Types.MAX_FRAME]); // 1 + MAX_FRAME > MAX_FRAME
        } catch (Frames.FrameException e) {
            recusou = true;
        }
        check("write recusa payload grande demais", recusou);

        System.out.println();
        System.out.println("=== Types ===");
        check("E2E_HEADER_LEN = 52", Types.E2E_HEADER_LEN == 52);
        check("NONCE_LEN = IV_BASE_LEN + SEQ_LEN",
                Types.NONCE_LEN == Types.IV_BASE_LEN + Types.SEQ_LEN);

        System.out.println();
        System.out.println("=== Log (confira visualmente) ===");
        Log.info("mensagem de informacao");
        Log.warn("mensagem de aviso");
        Log.error("mensagem de erro");
        Log.info("linha com\nquebra nao forja outra linha");

        byte[] chaveFalsa = new byte[Types.PK_LEN];
        Arrays.fill(chaveFalsa, (byte) 7);
        String fp = Log.fingerprint(chaveFalsa);
        Log.info("fingerprint da chave: " + fp);
        check("fingerprint tem 8 caracteres hex", fp.matches("[0-9a-f]{8}"));
        check("fingerprint e deterministico", fp.equals(Log.fingerprint(chaveFalsa)));

        UUID uuid = UUID.randomUUID();
        byte[] idBytes = new byte[Types.CLIENT_ID_LEN];
        java.nio.ByteBuffer.wrap(idBytes)
                .putLong(uuid.getMostSignificantBits())
                .putLong(uuid.getLeastSignificantBits());
        Log.info("client_id: " + Log.id(idBytes));
        check("id() devolve o mesmo UUID", Log.id(idBytes).equals(uuid.toString()));
        check("id() de tamanho errado => id-invalido", Log.id(new byte[5]).equals("id-invalido"));

        System.out.println();
        if (falhas == 0) {
            System.out.println("TUDO OK - etapa 1 aprovada.");
        } else {
            System.out.println(falhas + " teste(s) falharam.");
            System.exit(1);
        }
    }
}