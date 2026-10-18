package br.ufc.seginfo.common;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.HexFormat;
import java.util.UUID;

/**
 * Ponto unico de log do projeto.
 *
 * Regra da politica de logs: nunca registrar chaves, segredo Z, salt, nonce
 * ou conteudo de mensagem. Por isso info/warn/error so aceitam String.
 * Para identificar uma chave use fingerprint(); para um client_id use id().
 */
public final class Log {

    private static final DateTimeFormatter HORA = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");

    // Etiqueta que aparece em toda linha: "SERVER", "CLIENT"...
    private static volatile String tag = "APP";

    private Log() {
    }

    public static void setTag(String novaTag) {
        tag = novaTag;
    }

    public static void info(String msg) {
        escrever("INFO ", msg);
    }

    public static void warn(String msg) {
        escrever("WARN ", msg);
    }

    public static void error(String msg) {
        escrever("ERROR", msg);
    }

    // synchronized para linhas de threads diferentes nao se misturarem
    private static synchronized void escrever(String nivel, String msg) {
        // tira quebras de linha para ninguem forjar linhas falsas no log
        String limpa = msg.replace('\n', ' ').replace('\r', ' ');
        System.out.println(LocalTime.now().format(HORA) + " [" + tag + "] " + nivel + " " + limpa);
    }

    /**
     * "Identidade curta" de uma chave publica: 8 primeiros caracteres hex do SHA-256.
     * Serve para reconhecer uma chave no log sem mostra-la inteira.
     */
    public static String fingerprint(byte[] chavePublica) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(chavePublica);
            return HexFormat.of().formatHex(hash, 0, 4); // 4 bytes = 8 caracteres hex
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 nao disponivel", e);
        }
    }

    /** Converte os 16 bytes do client_id em texto de UUID (permitido no log). */
    public static String id(byte[] clientId) {
        if (clientId == null || clientId.length != Types.CLIENT_ID_LEN) {
            return "id-invalido";
        }
        ByteBuffer bb = ByteBuffer.wrap(clientId);
        return new UUID(bb.getLong(), bb.getLong()).toString();
    }
}