package br.ufc.seginfo.common;

/**
 * Constantes do protocolo. Cliente e servidor leem os mesmos valores daqui.
 * Nao tem logica: so guarda numeros com nome para nao espalhar "numeros magicos".
 */
public final class Types {

    private Types() {
        // classe so de constantes, ninguem cria objeto dela
    }

    // ---------- Tipos de frame (1 byte logo depois do tamanho) ----------

    // cliente -> servidor
    public static final byte HELLO = 0x01;

    // servidor -> cliente
    public static final byte SERVER_HELLO = 0x02;
    public static final byte REGISTERED = 0x03;
    public static final byte PEER_INFO = 0x04;
    public static final byte PEER_LEFT = 0x05;
    public static final byte ERROR = 0x06;

    // nos dois sentidos (o servidor so encaminha)
    public static final byte E2E = 0x10;

    // ---------- Tamanhos em bytes ----------

    public static final int CLIENT_ID_LEN = 16;  // UUID v4 binario
    public static final int PK_LEN = 32;         // chave publica X25519 raw
    public static final int SALT_LEN = 16;       // salt do HKDF
    public static final int KEY_LEN = 16;        // chave AES-128
    public static final int IV_BASE_LEN = 4;     // parte aleatoria do nonce
    public static final int SEQ_LEN = 8;         // contador (long, big-endian)
    public static final int NONCE_LEN = 12;      // IV_base (4) + seq_no (8)
    public static final int TAG_LEN = 16;        // tag do AES-GCM

    // Cabecalho do frame E2E: nonce + sender_id + recipient_id + seq_no
    public static final int E2E_HEADER_LEN =
            NONCE_LEN + CLIENT_ID_LEN + CLIENT_ID_LEN + SEQ_LEN;  // 52

    // ---------- Limites ----------

    public static final int MAX_PLAINTEXT = 4096;  // texto maximo por mensagem
    public static final int MAX_FRAME = 8192;      // maximo de (type + payload)
    public static final int MAX_CLIENTS = 100;
    public static final int PORT = 5000;
    public static final int HANDSHAKE_TIMEOUT_MS = 10_000;  // tempo maximo para concluir o handshake

    // Tamanhos validos do payload de um frame E2E (cabecalho + texto cifrado + tag)
    public static final int E2E_MIN_PAYLOAD = E2E_HEADER_LEN + TAG_LEN;                 // 68 (texto vazio)
    public static final int E2E_MAX_PAYLOAD = E2E_HEADER_LEN + MAX_PLAINTEXT + TAG_LEN; // 4164

    // ---------- Codigos de erro (frame ERROR) ----------

    public static final byte ERR_ID_IN_USE = 0x01;
    public static final byte ERR_SERVER_FULL = 0x02;
    public static final byte ERR_BAD_FRAME = 0x03;
    public static final byte ERR_BAD_HANDSHAKE = 0x04;
    public static final byte ERR_RECIPIENT_OFFLINE = 0x05;
}