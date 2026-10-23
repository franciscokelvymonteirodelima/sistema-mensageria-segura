package br.ufc.seginfo.client;

import br.ufc.seginfo.common.CryptoUtil;
import br.ufc.seginfo.common.Frames;
import br.ufc.seginfo.common.Types;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * Handshake do lado do cliente. O ponto principal: so aceitamos o servidor se
 *   (1) o certificado recebido for IDENTICO ao certificado pinado (server.crt), e
 *   (2) a assinatura RSA-PSS sobre H = SHA256(pk_server | pk_C | client_id | salt) for valida.
 * Isso impede que um impostor (MITM) se passe pelo servidor.
 */
public final class Handshake {

    private Handshake() {
    }

    /** O que o cliente precisa guardar depois do handshake. */
    public record Resultado(byte[] salt, long ultimoSeqServidor) {
    }

    /** Qualquer motivo para NAO confiar no servidor. */
    public static class HandshakeException extends Exception {
        public HandshakeException(String msg) {
            super(msg);
        }
    }

    public static Resultado executar(DataInputStream in, DataOutputStream out,
                                     byte[] clientId, byte[] pkC, X509Certificate pinado)
            throws IOException, HandshakeException {

        // 1) HELLO
        Frames.write(out, Types.HELLO, CryptoUtil.concat(clientId, pkC));

        // 2) SERVER_HELLO (ou ERROR)
        Frames.Frame f = Frames.read(in);
        if (f.type() == Types.ERROR) {
            throw new HandshakeException(descreverErro(f.payload()));
        }
        if (f.type() != Types.SERVER_HELLO) {
            throw new HandshakeException(String.format("resposta inesperada do servidor (tipo 0x%02x)", f.type()));
        }

        byte[] salt;
        byte[] certRecebido;
        byte[] assinatura;
        try {
            ByteBuffer bb = ByteBuffer.wrap(f.payload());
            salt = new byte[Types.SALT_LEN];
            bb.get(salt);
            certRecebido = new byte[Short.toUnsignedInt(bb.getShort())];
            bb.get(certRecebido);
            assinatura = new byte[Short.toUnsignedInt(bb.getShort())];
            bb.get(assinatura);
            if (bb.hasRemaining()) {
                throw new HandshakeException("SERVER_HELLO com bytes sobrando");
            }
        } catch (BufferUnderflowException e) {
            throw new HandshakeException("SERVER_HELLO truncado");
        }

        // 3) certificado igual ao pinado?
        byte[] pinadoDer;
        try {
            pinadoDer = pinado.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new HandshakeException("certificado pinado ilegivel");
        }
        if (!MessageDigest.isEqual(certRecebido, pinadoDer)) {
            throw new HandshakeException("certificado do servidor nao confere com o pinado");
        }

        // 4) assinatura valida? (usamos a chave do certificado PINADO, nao a recebida)
        byte[] h = CryptoUtil.hashHandshake(pinado.getPublicKey().getEncoded(), pkC, clientId, salt);
        if (!CryptoUtil.verificarPss(pinado.getPublicKey(), h, assinatura)) {
            throw new HandshakeException("assinatura RSA-PSS do servidor invalida");
        }

        // 5) REGISTERED: seq(8)
        Frames.Frame r = Frames.read(in);
        if (r.type() == Types.ERROR) {
            throw new HandshakeException(descreverErro(r.payload()));
        }
        if (r.type() != Types.REGISTERED || r.payload().length != Types.SEQ_LEN) {
            throw new HandshakeException("REGISTERED invalido");
        }
        long seq = ByteBuffer.wrap(r.payload()).getLong();
        if (seq < 0) { // so aceitamos seq maior que -1 (nenhum visto ainda)
            throw new HandshakeException("seq invalido no REGISTERED");
        }

        return new Resultado(salt, seq);
    }

    /** ERROR: seq(8) | codigo(1). */
    static String descreverErro(byte[] payload) {
        if (payload.length != Types.SEQ_LEN + 1) {
            return "erro do servidor (formato desconhecido)";
        }
        byte codigo = payload[Types.SEQ_LEN];
        return switch (codigo) {
            case Types.ERR_ID_IN_USE -> "client_id ja esta em uso";
            case Types.ERR_SERVER_FULL -> "servidor cheio";
            case Types.ERR_BAD_FRAME -> "servidor rejeitou o frame (framing invalido)";
            case Types.ERR_BAD_HANDSHAKE -> "servidor rejeitou o handshake";
            default -> String.format("erro do servidor (codigo 0x%02x)", codigo);
        };
    }
}