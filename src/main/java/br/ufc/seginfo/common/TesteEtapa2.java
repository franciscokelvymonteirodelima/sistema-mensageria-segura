package br.ufc.seginfo.common;

import javax.crypto.AEADBadTagException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * Teste manual da Etapa 2 (CryptoUtil). Rode o main e veja se tudo da [OK].
 * Varios testes usam vetores oficiais (RFC 7748, RFC 5869, McGrew-Viega do GCM):
 * se a nossa saida bate com a do documento oficial, a implementacao esta correta.
 */
public class TesteEtapa2 {

    static int falhas = 0;
    static final HexFormat HEX = HexFormat.of();

    static void check(String nome, boolean ok) {
        System.out.println((ok ? "[OK]     " : "[FALHOU] ") + nome);
        if (!ok) {
            falhas++;
        }
    }

    static byte[] h(String hex) {
        return HEX.parseHex(hex);
    }

    // true se decifrar lancar AEADBadTagException (adulteracao detectada)
    static boolean rejeitaGcm(byte[] chave, byte[] nonce, byte[] aad, byte[] ct) {
        try {
            CryptoUtil.aesGcmDecifrar(chave, nonce, aad, ct);
            return false;
        } catch (AEADBadTagException e) {
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    // monta a chave privada X25519 a partir dos 32 bytes raw (prefixo PKCS#8 fixo)
    static PrivateKey x25519Privada(String hexRaw) throws Exception {
        byte[] der = CryptoUtil.concat(h("302e020100300506032b656e04220420"), h(hexRaw));
        return KeyFactory.getInstance("X25519").generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    public static void main(String[] args) throws Exception {
        Log.setTag("TESTE");

        // ------------------------------------------------------------------
        System.out.println("=== X25519 (ECDH) ===");

        // Vetor oficial da RFC 7748, secao 6.1
        String alicePriv = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
        String alicePub = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
        String bobPriv = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
        String bobPub = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
        String zEsperado = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

        byte[] zAlice = CryptoUtil.ecdh(x25519Privada(alicePriv), h(bobPub));
        byte[] zBob = CryptoUtil.ecdh(x25519Privada(bobPriv), h(alicePub));
        check("vetor RFC 7748: Alice chega no Z oficial", HEX.formatHex(zAlice).equals(zEsperado));
        check("vetor RFC 7748: Bob chega no Z oficial", HEX.formatHex(zBob).equals(zEsperado));

        // Pares gerados de verdade
        KeyPair a = CryptoUtil.gerarParX25519();
        KeyPair b = CryptoUtil.gerarParX25519();
        KeyPair c = CryptoUtil.gerarParX25519(); // um "intruso"
        byte[] pkA = CryptoUtil.chavePublicaRaw(a.getPublic());
        byte[] pkB = CryptoUtil.chavePublicaRaw(b.getPublic());
        byte[] pkC = CryptoUtil.chavePublicaRaw(c.getPublic());

        check("chave publica raw tem 32 bytes", pkA.length == 32);
        check("raw -> PublicKey -> raw devolve a mesma chave",
                Arrays.equals(pkA, CryptoUtil.chavePublicaRaw(CryptoUtil.chavePublicaDeRaw(pkA))));

        byte[] zAB = CryptoUtil.ecdh(a.getPrivate(), pkB);
        byte[] zBA = CryptoUtil.ecdh(b.getPrivate(), pkA);
        check("A e B chegam ao mesmo Z", Arrays.equals(zAB, zBA));
        check("Z tem 32 bytes", zAB.length == 32);
        check("intruso C (so com chaves publicas) nao chega ao mesmo Z",
                !Arrays.equals(zAB, CryptoUtil.ecdh(c.getPrivate(), pkA))
                        && !Arrays.equals(zAB, CryptoUtil.ecdh(c.getPrivate(), pkB)));
        check("dois pares gerados sao diferentes", !Arrays.equals(pkA, pkB) && !Arrays.equals(pkB, pkC));

        boolean recusouTamanho = false;
        try {
            CryptoUtil.chavePublicaDeRaw(new byte[31]);
        } catch (GeneralSecurityException e) {
            recusouTamanho = true;
        }
        check("chave publica com tamanho errado e recusada", recusouTamanho);

        boolean recusouZero = false;
        try {
            CryptoUtil.ecdh(a.getPrivate(), new byte[32]); // ponto de ordem baixa
        } catch (GeneralSecurityException e) {
            recusouZero = true;
        }
        check("chave publica toda zero (ordem baixa) e recusada", recusouZero);

        // ------------------------------------------------------------------
        System.out.println();
        System.out.println("=== HKDF-SHA256 ===");

        // Vetor oficial da RFC 5869, Test Case 1
        byte[] ikm = h("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = h("000102030405060708090a0b0c");
        byte[] info = h("f0f1f2f3f4f5f6f7f8f9");
        byte[] prk = CryptoUtil.hkdfExtract(salt, ikm);
        byte[] okm = CryptoUtil.hkdfExpand(prk, info, 42);
        check("vetor RFC 5869: PRK confere",
                HEX.formatHex(prk).equals("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"));
        check("vetor RFC 5869: OKM (42 bytes) confere",
                HEX.formatHex(okm).equals("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                        + "34007208d5b887185865"));

        byte[] saltPar = CryptoUtil.aleatorio(Types.SALT_LEN);
        CryptoUtil.ChavesE2E kA = CryptoUtil.derivarChavesE2E(zAB, saltPar);
        CryptoUtil.ChavesE2E kB = CryptoUtil.derivarChavesE2E(zBA, saltPar);
        check("os dois lados derivam as mesmas chaves A2B e B2A",
                Arrays.equals(kA.a2b(), kB.a2b()) && Arrays.equals(kA.b2a(), kB.b2a()));
        check("chaves tem 16 bytes", kA.a2b().length == 16 && kA.b2a().length == 16);
        check("A2B e B2A sao diferentes", !Arrays.equals(kA.a2b(), kA.b2a()));
        CryptoUtil.ChavesE2E kOutroSalt = CryptoUtil.derivarChavesE2E(zAB, CryptoUtil.aleatorio(Types.SALT_LEN));
        check("salt diferente => chaves diferentes (reconexao muda as chaves)",
                !Arrays.equals(kA.a2b(), kOutroSalt.a2b()));

        // ------------------------------------------------------------------
        System.out.println();
        System.out.println("=== AES-128-GCM ===");

        // Vetor oficial (McGrew-Viega, Test Case 2): chave 0, nonce 0, texto de 16 bytes zero
        byte[] gcmSaida = CryptoUtil.aesGcmCifrar(new byte[16], new byte[12], new byte[0], new byte[16]);
        check("vetor oficial GCM: ciphertext+tag confere",
                HEX.formatHex(gcmSaida).equals("0388dace60b6a392f328c2b971b2fe78"
                        + "ab6e47d42cec13bdf53a67b21257bddf"));

        byte[] chave = kA.a2b();
        byte[] ivBase = CryptoUtil.aleatorio(Types.IV_BASE_LEN);
        byte[] nonce = CryptoUtil.montarNonce(ivBase, 0);
        byte[] aad = CryptoUtil.concat(CryptoUtil.aleatorio(16), CryptoUtil.aleatorio(16), new byte[8]);
        byte[] texto = "mensagem secreta de teste".getBytes();
        byte[] ct = CryptoUtil.aesGcmCifrar(chave, nonce, aad, texto);

        check("ciphertext = texto + 16 bytes de tag", ct.length == texto.length + 16);
        check("decifrar devolve o texto original",
                Arrays.equals(texto, CryptoUtil.aesGcmDecifrar(chave, nonce, aad, ct)));

        // bitflip em TODAS as posicoes (ciphertext e tag): todas devem ser rejeitadas
        boolean todasRejeitadas = true;
        for (int i = 0; i < ct.length; i++) {
            byte[] adulterado = ct.clone();
            adulterado[i] ^= 0x01;
            if (!rejeitaGcm(chave, nonce, aad, adulterado)) {
                todasRejeitadas = false;
            }
        }
        check("bitflip em qualquer byte do ciphertext/tag e rejeitado (" + ct.length + " posicoes)",
                todasRejeitadas);

        byte[] aadErrado = aad.clone();
        aadErrado[0] ^= 0x01;
        check("AAD alterado (ex: outro remetente) e rejeitado", rejeitaGcm(chave, nonce, aadErrado, ct));
        check("nonce diferente e rejeitado",
                rejeitaGcm(chave, CryptoUtil.montarNonce(ivBase, 1), aad, ct));
        check("chave errada (B2A em vez de A2B) e rejeitada", rejeitaGcm(kA.b2a(), nonce, aad, ct));
        check("ciphertext truncado e rejeitado",
                rejeitaGcm(chave, nonce, aad, Arrays.copyOf(ct, ct.length - 1)));

        byte[] ct2 = CryptoUtil.aesGcmCifrar(chave, CryptoUtil.montarNonce(ivBase, 1), aad, texto);
        check("mesmo texto com nonce diferente gera ciphertext diferente", !Arrays.equals(ct, ct2));

        byte[] n = CryptoUtil.montarNonce(new byte[]{1, 2, 3, 4}, 5);
        check("nonce = IV_base(4B) || seq_no(8B big-endian)",
                HEX.formatHex(n).equals("01020304" + "0000000000000005"));

        // ------------------------------------------------------------------
        System.out.println();
        System.out.println("=== RSA-PSS e hash do handshake ===");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair rsa = kpg.generateKeyPair();
        KeyPair rsaOutro = kpg.generateKeyPair();

        byte[] pkServerDer = rsa.getPublic().getEncoded();
        byte[] clientId = CryptoUtil.aleatorio(Types.CLIENT_ID_LEN);
        byte[] saltSrv = CryptoUtil.aleatorio(Types.SALT_LEN);
        byte[] hh = CryptoUtil.hashHandshake(pkServerDer, pkA, clientId, saltSrv);

        check("hash do handshake tem 32 bytes e e deterministico",
                hh.length == 32 && Arrays.equals(hh, CryptoUtil.hashHandshake(pkServerDer, pkA, clientId, saltSrv)));
        check("mudar pk_client muda o hash",
                !Arrays.equals(hh, CryptoUtil.hashHandshake(pkServerDer, pkB, clientId, saltSrv)));
        check("mudar client_id muda o hash",
                !Arrays.equals(hh, CryptoUtil.hashHandshake(pkServerDer, pkA, CryptoUtil.aleatorio(16), saltSrv)));
        check("mudar salt muda o hash",
                !Arrays.equals(hh, CryptoUtil.hashHandshake(pkServerDer, pkA, clientId, CryptoUtil.aleatorio(16))));

        byte[] assinatura = CryptoUtil.assinarPss(rsa.getPrivate(), hh);
        check("assinatura tem 256 bytes (RSA-2048)", assinatura.length == 256);
        check("assinatura valida e aceita", CryptoUtil.verificarPss(rsa.getPublic(), hh, assinatura));

        byte[] hhAdulterado = hh.clone();
        hhAdulterado[0] ^= 0x01;
        check("hash alterado => assinatura recusada", !CryptoUtil.verificarPss(rsa.getPublic(), hhAdulterado, assinatura));

        byte[] assAdulterada = assinatura.clone();
        assAdulterada[10] ^= 0x01;
        check("assinatura adulterada e recusada", !CryptoUtil.verificarPss(rsa.getPublic(), hh, assAdulterada));
        check("chave de outro servidor (impostor) e recusada",
                !CryptoUtil.verificarPss(rsaOutro.getPublic(), hh, assinatura));

        byte[] assinatura2 = CryptoUtil.assinarPss(rsa.getPrivate(), hh);
        check("PSS e randomizado: duas assinaturas diferem, mas as duas validam",
                !Arrays.equals(assinatura, assinatura2) && CryptoUtil.verificarPss(rsa.getPublic(), hh, assinatura2));

        // ------------------------------------------------------------------
        System.out.println();
        if (falhas == 0) {
            System.out.println("TUDO OK - etapa 2 aprovada.");
        } else {
            System.out.println(falhas + " teste(s) falharam.");
            System.exit(1);
        }
    }
}