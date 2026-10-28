package br.ufc.seginfo.client;

import br.ufc.seginfo.common.Ids;
import br.ufc.seginfo.common.Types;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A "lista de contatos" do cliente: quem esta online e qual e a chave publica de cada um.
 * E atualizada pelas mensagens PEER_INFO (entrou) e PEER_LEFT (saiu) do servidor.
 *
 * Nesta etapa guarda so os dados crus do peer. Na Etapa 5 cada entrada ganha as chaves
 * AES derivadas (ECDH + HKDF) e os contadores.
 */
public final class PeerTable {

    /** O que o servidor nos conta sobre um peer. O salt e o salt_srv DELE (usado no HKDF do par). */
    public record PeerInfo(byte[] clientId, byte[] chavePublica, byte[] salt) {
        public UUID uuid() {
            return Ids.paraUuid(clientId);
        }
    }

    private final ConcurrentHashMap<UUID, PeerInfo> peers = new ConcurrentHashMap<>();

    /** Adiciona ou SUBSTITUI (se o peer reconectou, chega com chave e salt novos). */
    public void adicionar(PeerInfo info) {
        peers.put(info.uuid(), info);
    }

    /** true se o peer estava na tabela. */
    public boolean remover(UUID id) {
        return peers.remove(id) != null;
    }

    public PeerInfo buscar(UUID id) {
        return peers.get(id);
    }

    public int total() {
        return peers.size();
    }

    /** Lista ordenada por client_id, para a saida ser sempre igual. */
    public List<PeerInfo> listar() {
        List<PeerInfo> lista = new ArrayList<>(peers.values());
        lista.sort(Comparator.comparing(PeerInfo::uuid));
        return lista;
    }

    /**
     * Le o payload do PEER_INFO: seq(8) | client_id(16) | pk(32) | salt(16).
     * Devolve null se o tamanho estiver errado. (O seq quem confere e quem chama.)
     */
    public static PeerInfo parsearPeerInfo(byte[] payload) {
        int esperado = Types.SEQ_LEN + Types.CLIENT_ID_LEN + Types.PK_LEN + Types.SALT_LEN; // 72
        if (payload.length != esperado) {
            return null;
        }
        ByteBuffer bb = ByteBuffer.wrap(payload);
        bb.position(Types.SEQ_LEN); // pula o seq
        byte[] id = new byte[Types.CLIENT_ID_LEN];
        byte[] pk = new byte[Types.PK_LEN];
        byte[] salt = new byte[Types.SALT_LEN];
        bb.get(id);
        bb.get(pk);
        bb.get(salt);
        return new PeerInfo(id, pk, salt);
    }

    /** Le o client_id do payload do PEER_LEFT: seq(8) | client_id(16). Null se o tamanho estiver errado. */
    public static UUID parsearPeerLeft(byte[] payload) {
        if (payload.length != Types.SEQ_LEN + Types.CLIENT_ID_LEN) {
            return null;
        }
        byte[] id = new byte[Types.CLIENT_ID_LEN];
        System.arraycopy(payload, Types.SEQ_LEN, id, 0, Types.CLIENT_ID_LEN);
        return Ids.paraUuid(id);
    }
}