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

    /*O cliente envia sua mensagem inicial para começar o
    protocolo de comunicação. Dependendo da implementação,
    pode conter seu identificador e sua chave pública.*/
    public static final byte HELLO = 0x01;

    // servidor -> cliente
    /*O servidor responde ao início da comunicação.
    Pode informar dados necessários para o cliente
    continuar o protocolo.*/
    public static final byte SERVER_HELLO = 0x02;

    /*Informa que o cliente foi registrado.
    O cliente pode usar essa resposta para saber
    que sua identificação foi aceita.*/
    public static final byte REGISTERED = 0x03;

    /*Transporta informações sobre outro cliente (peer),
    por exemplo, seu identificador e sua chave pública,
    conforme o formato definido no protocolo.*/
    public static final byte PEER_INFO = 0x04;

    /*Informa que outro cliente saiu ou desconectou.
    Os demais clientes podem atualizar sua lista de
    contatos conectados.*/
    public static final byte PEER_LEFT = 0x05;

    /*Indica que ocorreu um erro no protocolo.
    O conteúdo da mensagem informa qual erro aconteceu.*/
    public static final byte ERROR = 0x06;

    // nos dois sentidos (o servidor so encaminha)
    /*Representa uma mensagem criptografada de ponta a ponta.
    O servidor encaminha o conteúdo ao destinatário,
    sem precisar descriptografar a mensagem.*/
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

    // ---------- Codigos de erro (frame ERROR) ----------

    /*Dois clientes tentam se registrar com o mesmo identificador.
    Impacto: o servidor pode rejeitar o novo registro
    para não confundir as identidades dos clientes.*/
    public static final byte ERR_ID_IN_USE = 0x01;

    /*O limite de clientes foi atingido.
    Impacto: o servidor recusa novas conexões ou
    registros até haver espaço disponível.*/
    public static final byte ERR_SERVER_FULL = 0x02;

    /*O servidor recebe uma mensagem malformada, com tamanho incorreto,
    estrutura incompleta ou formato incompatível com o protocolo.
    Impacto: o servidor pode descartar a mensagem e,
    dependendo da gravidade, encerrar a conexão.*/
    public static final byte ERR_BAD_FRAME = 0x03;

    /*O cliente não conclui corretamente a etapa inicial de comunicação,
    por exemplo, envia dados obrigatórios ausentes ou inconsistentes.
    Impacto: o servidor pode rejeitar o cliente antes de permitir a
    troca normal de mensagens.*/
    public static final byte ERR_BAD_HANDSHAKE = 0x04;

}