package br.ufc.seginfo.common;

import java.nio.ByteBuffer;
import java.util.UUID;

/**
 * client_id: UUID v4 de 16 bytes binarios (network byte order).
 * Esta classe converte entre UUID (texto/objeto) e os 16 bytes que vao no protocolo.
 */
public final class Ids {

    private Ids() {
    }

    /** Gera um client_id novo (UUID v4 aleatorio) como 16 bytes. */
    public static byte[] novoClientId() {
        return paraBytes(UUID.randomUUID());
    }

    public static byte[] paraBytes(UUID uuid) {
        return ByteBuffer.allocate(Types.CLIENT_ID_LEN)
                .putLong(uuid.getMostSignificantBits())
                .putLong(uuid.getLeastSignificantBits())
                .array();
    }

    public static UUID paraUuid(byte[] bytes) {
        if (bytes.length != Types.CLIENT_ID_LEN) {
            throw new IllegalArgumentException("client_id deve ter " + Types.CLIENT_ID_LEN + " bytes");
        }
        ByteBuffer bb = ByteBuffer.wrap(bytes);
        return new UUID(bb.getLong(), bb.getLong());
    }
}