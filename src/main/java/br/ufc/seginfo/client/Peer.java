package br.ufc.seginfo.client;

import br.ufc.seginfo.common.CryptoUtil;
import br.ufc.seginfo.common.E2EFrame;
import br.ufc.seginfo.common.Ids;
import br.ufc.seginfo.common.Types;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.UUID;

/**
 * A "ficha" de um contato: as chaves AES desta conversa, os contadores e as regras
 * de cifrar e decifrar. Existe um Peer por contato online.
 *
 * Direcoes: "A" e o client_id MENOR (bytes sem sinal), "B" o maior.
 *   - se eu sou A: envio com A2B e recebo com B2A
 *   - se eu sou B: envio com B2A e recebo com A2B
 * O salt do par e o salt_srv de A. Assim os dois lados chegam as mesmas chaves sem combinar nada.
 */
public final class Peer {

    /** Por que uma mensagem recebida foi rejeitada. So o motivo vai para o log, nunca o conteudo. */
    public enum Rejeicao {
        ENDERECO_INVALIDO,   // remetente ou destinatario nao sao os esperados
        NONCE_INCOERENTE,    // o seq_no dentro do nonce nao bate com o do cabecalho
        IV_BASE_DIFERENTE,   // o IV_base mudou no meio da conversa
        TAG_INVALIDA,        // adulterada (ou chave errada): a tag do GCM nao bateu
        REPLAY               // mensagem autentica, mas repetida ou antiga (seq_no nao e maior que o ultimo)
    }

    /** Resultado de decifrar: ou vem o texto, ou vem o motivo da rejeicao. */
    public record Resultado(byte[] texto, Rejeicao rejeicao) {
        public boolean ok() {
            return rejeicao == null;
        }
    }

    private final byte[] meuId;
    private final byte[] peerId;
    private final PeerTable.PeerInfo info;
    private final byte[] keySend;
    private final byte[] keyRecv;
    private final byte[] ivBaseSend = CryptoUtil.aleatorio(Types.IV_BASE_LEN); // sorteado por direcao
    private byte[] ivBaseRecv = null;  // fixado pela primeira mensagem valida recebida
    private long seqSend = 0;          // proximo seq_no a usar
    private long seqRecv = -1;         // ultimo seq_no aceito

    private Peer(byte[] meuId, PeerTable.PeerInfo info, byte[] keySend, byte[] keyRecv) {
        this.meuId = meuId;
        this.peerId = info.clientId();
        this.info = info;
        this.keySend = keySend;
        this.keyRecv = keyRecv;
    }

    /**
     * Cria o Peer: calcula Z = ECDH(minha sk, pk do peer), deriva as duas chaves via HKDF
     * e descarta o Z. Se o peer reconectar, chega um PEER_INFO novo e um Peer novo
     * (chaves novas, contadores do zero).
     *
     * @param meuSalt o salt_srv que o servidor me deu no handshake
     */
    public static Peer criar(byte[] meuId, PrivateKey minhaSk, PeerTable.PeerInfo info, byte[] meuSalt)
            throws GeneralSecurityException {
        int comparacao = Arrays.compareUnsigned(meuId, info.clientId());
        if (comparacao == 0) {
            throw new InvalidKeyException("peer com o meu proprio client_id");
        }
        boolean souA = comparacao < 0;
        byte[] saltPar = souA ? meuSalt : info.salt();

        byte[] z = CryptoUtil.ecdh(minhaSk, info.chavePublica());
        CryptoUtil.ChavesE2E chaves;
        try {
            chaves = CryptoUtil.derivarChavesE2E(z, saltPar);
        } finally {
            Arrays.fill(z, (byte) 0); // o Z nao fica na memoria
        }
        return new Peer(meuId, info,
                souA ? chaves.a2b() : chaves.b2a(),
                souA ? chaves.b2a() : chaves.a2b());
    }

    public UUID uuid() {
        return Ids.paraUuid(peerId);
    }

    public PeerTable.PeerInfo info() {
        return info;
    }

    /** Ultimo seq_no aceito deste peer (-1 se nenhum). Util nos testes. */
    public synchronized long ultimoSeqAceito() {
        return seqRecv;
    }

    /**
     * Cifra um texto para este peer e devolve o payload do frame E2E, pronto para enviar.
     * synchronized: o seq_no (e portanto o nonce) NUNCA se repete, mesmo com duas threads.
     */
    public synchronized byte[] cifrar(byte[] plaintext) {
        if (plaintext.length > Types.MAX_PLAINTEXT) {
            throw new IllegalArgumentException("mensagem maior que " + Types.MAX_PLAINTEXT + " bytes");
        }
        long seq = seqSend++; // gasto mesmo se o envio falhar: nunca se reaproveita um seq_no
        byte[] nonce = CryptoUtil.montarNonce(ivBaseSend, seq);
        byte[] aad = E2EFrame.aad(meuId, peerId, seq);
        byte[] cifrado = CryptoUtil.aesGcmCifrar(keySend, nonce, aad, plaintext);
        return new E2EFrame(nonce, meuId, peerId, seq, cifrado).serializar();
    }

    /**
     * Confere e decifra uma mensagem deste peer. Ordem das conferencias:
     *   1) endereco  2) nonce coerente  3) IV_base  4) tag do GCM  5) seq_no maior que o ultimo
     * O estado (IV_base e seq_recv) so muda se TUDO passar. Assim uma mensagem forjada
     * nunca atrapalha as verdadeiras.
     */
    public synchronized Resultado decifrar(E2EFrame f) {
        if (!Arrays.equals(f.senderId(), peerId) || !Arrays.equals(f.recipientId(), meuId)) {
            return rejeitar(Rejeicao.ENDERECO_INVALIDO);
        }
        long seqNoNonce = ByteBuffer.wrap(f.nonce()).getLong(Types.IV_BASE_LEN);
        if (seqNoNonce != f.seqNo()) {
            return rejeitar(Rejeicao.NONCE_INCOERENTE);
        }
        byte[] ivBase = Arrays.copyOfRange(f.nonce(), 0, Types.IV_BASE_LEN);
        if (ivBaseRecv != null && !Arrays.equals(ivBaseRecv, ivBase)) {
            return rejeitar(Rejeicao.IV_BASE_DIFERENTE);
        }

        byte[] aad = E2EFrame.aad(f.senderId(), f.recipientId(), f.seqNo());
        byte[] texto;
        try {
            texto = CryptoUtil.aesGcmDecifrar(keyRecv, f.nonce(), aad, f.cifrado());
        } catch (GeneralSecurityException e) {
            return rejeitar(Rejeicao.TAG_INVALIDA);
        }

        // a mensagem e autentica; resta saber se e nova
        if (f.seqNo() <= seqRecv) {
            return rejeitar(Rejeicao.REPLAY);
        }
        ivBaseRecv = ivBase;
        seqRecv = f.seqNo();
        return new Resultado(texto, null);
    }

    private static Resultado rejeitar(Rejeicao motivo) {
        return new Resultado(null, motivo);
    }
}