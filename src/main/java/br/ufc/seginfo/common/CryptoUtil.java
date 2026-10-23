package br.ufc.seginfo.common;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * Caixa de ferramentas de criptografia do projeto. Todas as operacoes
 * criptograficas passam por aqui:
 *
 *   1) X25519  - gerar chaves e calcular o segredo compartilhado Z (ECDH)
 *   2) HKDF    - transformar Z em chaves AES de 16 bytes (HMAC-SHA256)
 *   3) AES-GCM - cifrar/decifrar com deteccao de adulteracao (AEAD)
 *   4) RSA-PSS - assinatura do servidor no handshake
 *
 * Convencao de erros:
 *  - Dado que vem da rede e pode estar errado (chave publica, mensagem cifrada)
 *    lanca GeneralSecurityException, para quem chamou tratar e rejeitar.
 *  - Falhas "impossiveis" (algoritmo inexistente) viram IllegalStateException.
 */
public final class CryptoUtil {

    private static final SecureRandom RANDOM = new SecureRandom();

    // Uma chave publica X25519 em formato X.509 (DER) e sempre este prefixo fixo
    // seguido dos 32 bytes raw. Usamos isso para converter raw <-> objeto Java.
    private static final byte[] X25519_X509_PREFIX = HexFormat.of().parseHex("302a300506032b656e032100");

    private CryptoUtil() {
    }

    // =====================================================================
    // Utilitarios
    // =====================================================================

    /** n bytes aleatorios criptograficamente seguros (salt, IV_base...). */
    public static byte[] aleatorio(int n) {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }

    /** Junta varios arrays em um so. */
    public static byte[] concat(byte[]... partes) {
        int total = 0;
        for (byte[] p : partes) {
            total += p.length;
        }
        byte[] r = new byte[total];
        int pos = 0;
        for (byte[] p : partes) {
            System.arraycopy(p, 0, r, pos, p.length);
            pos += p.length;
        }
        return r;
    }

    /** SHA-256 de varios pedacos concatenados. */
    public static byte[] sha256(byte[]... partes) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (byte[] p : partes) {
                md.update(p);
            }
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 nao disponivel", e);
        }
    }

    // =====================================================================
    // 1) X25519 (ECDHE)
    // =====================================================================

    /** Gera um par de chaves X25519 efemero. A privada (sk) nunca sai da maquina. */
    public static KeyPair gerarParX25519() {
        try {
            return KeyPairGenerator.getInstance("X25519").generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("X25519 nao disponivel", e);
        }
    }

    /** Extrai os 32 bytes raw da chave publica (os ultimos 32 bytes do encoding X.509). */
    public static byte[] chavePublicaRaw(PublicKey pk) {
        byte[] der = pk.getEncoded();
        return Arrays.copyOfRange(der, der.length - Types.PK_LEN, der.length);
    }

    /** Reconstroi o objeto PublicKey a partir dos 32 bytes raw recebidos da rede. */
    public static PublicKey chavePublicaDeRaw(byte[] raw) throws GeneralSecurityException {
        if (raw == null || raw.length != Types.PK_LEN) {
            throw new InvalidKeyException("chave publica X25519 deve ter " + Types.PK_LEN + " bytes");
        }
        byte[] der = concat(X25519_X509_PREFIX, raw);
        return KeyFactory.getInstance("X25519").generatePublic(new X509EncodedKeySpec(der));
    }

    /**
     * Z = ECDH(sk, pk_peer). Os dois lados chegam ao mesmo Z, e Z nunca e transmitido.
     * Rejeita resultado todo zero (chave publica maliciosa de "ordem baixa").
     */
    public static byte[] ecdh(PrivateKey sk, byte[] pkPeerRaw) throws GeneralSecurityException {
        PublicKey pub = chavePublicaDeRaw(pkPeerRaw);
        KeyAgreement ka = KeyAgreement.getInstance("X25519");
        ka.init(sk);
        ka.doPhase(pub, true);
        byte[] z = ka.generateSecret();

        int acumulado = 0;
        for (byte b : z) {
            acumulado |= b;
        }
        if (acumulado == 0) {
            throw new InvalidKeyException("segredo ECDH nulo (chave publica invalida)");
        }
        return z;
    }

    // =====================================================================
    // 2) HKDF-SHA256 (RFC 5869)
    // =====================================================================

    /** Chaves AES-128 de cada direcao. "A" e o client_id menor, "B" o maior. */
    public record ChavesE2E(byte[] a2b, byte[] b2a) {
    }

    /** HKDF-Extract: PRK = HMAC(salt, IKM). */
    public static byte[] hkdfExtract(byte[] salt, byte[] ikm) {
        // HMAC nao aceita chave vazia; a RFC manda usar zeros do tamanho do hash
        byte[] chave = (salt == null || salt.length == 0) ? new byte[32] : salt;
        return hmacSha256(chave, ikm);
    }

    /** HKDF-Expand: gera 'len' bytes a partir do PRK e de um rotulo (info). */
    public static byte[] hkdfExpand(byte[] prk, byte[] info, int len) {
        if (len < 1 || len > 255 * 32) {
            throw new IllegalArgumentException("tamanho de saida HKDF invalido: " + len);
        }
        byte[] okm = new byte[len];
        byte[] t = new byte[0];
        int pos = 0;
        for (int i = 1; pos < len; i++) {
            // T(i) = HMAC(PRK, T(i-1) | info | i)
            t = hmacSha256(prk, t, info, new byte[]{(byte) i});
            int n = Math.min(t.length, len - pos);
            System.arraycopy(t, 0, okm, pos, n);
            pos += n;
        }
        return okm;
    }

    /** Deriva as duas chaves E2E (A2B e B2A, 16 bytes cada) a partir de Z e do salt do par. */
    public static ChavesE2E derivarChavesE2E(byte[] z, byte[] saltPar) {
        byte[] prk = hkdfExtract(saltPar, z);
        byte[] a2b = hkdfExpand(prk, "A2B".getBytes(StandardCharsets.US_ASCII), Types.KEY_LEN);
        byte[] b2a = hkdfExpand(prk, "B2A".getBytes(StandardCharsets.US_ASCII), Types.KEY_LEN);
        return new ChavesE2E(a2b, b2a);
    }

    private static byte[] hmacSha256(byte[] chave, byte[]... partes) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(chave, "HmacSHA256"));
            for (byte[] p : partes) {
                mac.update(p);
            }
            return mac.doFinal();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 nao disponivel", e);
        }
    }

    // =====================================================================
    // 3) AES-128-GCM
    // =====================================================================

    /**
     * Monta o nonce de 12 bytes: IV_base (4B) || seq_no (8B, big-endian).
     * Cada par (chave, nonce) so pode ser usado UMA vez; quem garante isso e o seq_no crescente.
     */
    public static byte[] montarNonce(byte[] ivBase, long seqNo) {
        if (ivBase.length != Types.IV_BASE_LEN) {
            throw new IllegalArgumentException("IV_base deve ter " + Types.IV_BASE_LEN + " bytes");
        }
        return ByteBuffer.allocate(Types.NONCE_LEN).put(ivBase).putLong(seqNo).array();
    }

    /** Cifra e devolve ciphertext || tag (tag de 16 bytes no final). O AAD e autenticado, mas nao cifrado. */
    public static byte[] aesGcmCifrar(byte[] chave, byte[] nonce, byte[] aad, byte[] plaintext) {
        validarChaveENonce(chave, nonce);
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(chave, "AES"),
                    new GCMParameterSpec(Types.TAG_LEN * 8, nonce));
            c.updateAAD(aad);
            return c.doFinal(plaintext);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("falha ao cifrar", e);
        }
    }

    /**
     * Decifra ciphertext || tag. Se qualquer bit do ciphertext, da tag, do nonce
     * ou do AAD estiver diferente, lanca AEADBadTagException (subclasse de GeneralSecurityException).
     * Esse e o teste de "bitflip" do enunciado.
     */
    public static byte[] aesGcmDecifrar(byte[] chave, byte[] nonce, byte[] aad, byte[] cifradoMaisTag)
            throws GeneralSecurityException {
        validarChaveENonce(chave, nonce);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(chave, "AES"),
                new GCMParameterSpec(Types.TAG_LEN * 8, nonce));
        c.updateAAD(aad);
        return c.doFinal(cifradoMaisTag);
    }

    private static void validarChaveENonce(byte[] chave, byte[] nonce) {
        if (chave.length != Types.KEY_LEN) {
            throw new IllegalArgumentException("chave AES deve ter " + Types.KEY_LEN + " bytes");
        }
        if (nonce.length != Types.NONCE_LEN) {
            throw new IllegalArgumentException("nonce deve ter " + Types.NONCE_LEN + " bytes");
        }
    }

    // =====================================================================
    // 4) RSA-PSS (autenticacao do servidor)
    // =====================================================================

    /**
     * H = SHA256(pk_server_DER | pk_client | client_id | salt).
     * pk_server_DER sao os bytes da chave publica RSA do certificado.
     * Quem assina (servidor) e quem verifica (cliente) tem que calcular exatamente igual.
     */
    public static byte[] hashHandshake(byte[] pkServerDer, byte[] pkClient, byte[] clientId, byte[] salt) {
        if (pkClient.length != Types.PK_LEN || clientId.length != Types.CLIENT_ID_LEN
                || salt.length != Types.SALT_LEN) {
            throw new IllegalArgumentException("tamanho invalido em pk_client, client_id ou salt");
        }
        return sha256(pkServerDer, pkClient, clientId, salt);
    }

    /** Assina com RSA-PSS (SHA-256, MGF1-SHA256, salt de 32 bytes). */
    public static byte[] assinarPss(PrivateKey sk, byte[] dados) {
        try {
            Signature s = Signature.getInstance("RSASSA-PSS");
            s.setParameter(parametrosPss());
            s.initSign(sk);
            s.update(dados);
            return s.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("falha ao assinar", e);
        }
    }

    /** Verifica a assinatura RSA-PSS. Qualquer problema (assinatura invalida, chave errada) da false. */
    public static boolean verificarPss(PublicKey pk, byte[] dados, byte[] assinatura) {
        try {
            Signature s = Signature.getInstance("RSASSA-PSS");
            s.setParameter(parametrosPss());
            s.initVerify(pk);
            s.update(dados);
            return s.verify(assinatura);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    private static PSSParameterSpec parametrosPss() {
        return new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    }
}