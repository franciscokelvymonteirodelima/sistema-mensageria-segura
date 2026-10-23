package br.ufc.seginfo.common;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.util.Enumeration;

/**
 * Carregamento de chave e certificado do servidor.
 *
 *  - Servidor: le um keystore PKCS12 (server.p12) com a chave privada RSA + certificado.
 *  - Cliente:  le so o certificado (server.crt), que fica "pinado" (fixado) no cliente.
 */
public final class Certs {

    private Certs() {
    }

    /** Chave privada RSA + certificado autoassinado do servidor. */
    public record Identidade(PrivateKey chavePrivada, X509Certificate certificado) {
    }

    /** Le o keystore PKCS12 do servidor. Exige RSA de pelo menos 2048 bits. */
    public static Identidade carregarIdentidade(Path p12, char[] senha)
            throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(p12)) {
            ks.load(in, senha);
        }

        String alias = null;
        for (Enumeration<String> e = ks.aliases(); e.hasMoreElements(); ) {
            String a = e.nextElement();
            if (ks.isKeyEntry(a)) {
                alias = a;
                break;
            }
        }
        if (alias == null) {
            throw new KeyStoreException("o keystore nao tem nenhuma chave privada");
        }

        PrivateKey sk = (PrivateKey) ks.getKey(alias, senha);
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);

        if (!(sk instanceof RSAKey rsa) || rsa.getModulus().bitLength() < 2048) {
            throw new KeyStoreException("a chave do servidor deve ser RSA de pelo menos 2048 bits");
        }
        return new Identidade(sk, cert);
    }

    /** Le um certificado X.509 de arquivo (aceita PEM ou DER). */
    public static X509Certificate carregarCertificado(Path arquivo) throws IOException, CertificateException {
        try (InputStream in = Files.newInputStream(arquivo)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
    }
}