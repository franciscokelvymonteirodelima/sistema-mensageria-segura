package br.ufc.seginfo.server;

import br.ufc.seginfo.common.Types;

import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A "agenda" do servidor: quem esta online.
 *
 * Nesta etapa so guarda a tabela de sessoes. Na Etapa 4 ganha o aviso de
 * PEER_INFO / PEER_LEFT, e na Etapa 5 o encaminhamento dos frames E2E.
 */
public final class Router {

    private final ConcurrentHashMap<UUID, Session> sessoes = new ConcurrentHashMap<>();

    /** true se ainda cabe mais um cliente. (Checagem aproximada: nao e atomica com registrar.) */
    public boolean cheio() {
        return sessoes.size() >= Types.MAX_CLIENTS;
    }

    /** Registra a sessao. Devolve false se o client_id ja estiver em uso (atomico). */
    public boolean registrar(Session sessao) {
        return sessoes.putIfAbsent(sessao.uuid(), sessao) == null;
    }

    /** Remove so se a sessao registrada for ESTA (nao derruba outra com o mesmo id). */
    public void remover(Session sessao) {
        sessoes.remove(sessao.uuid(), sessao);
    }

    public Session buscar(UUID id) {
        return sessoes.get(id);
    }

    public int total() {
        return sessoes.size();
    }
}