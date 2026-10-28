package br.ufc.seginfo.server;

import br.ufc.seginfo.common.Log;
import br.ufc.seginfo.common.Types;

import java.io.IOException;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A "agenda" do servidor: quem esta online, e quem precisa saber de quem.
 *
 * Duas fases para cada cliente:
 *   1) registrar()        - reserva o client_id na tabela (acontece logo depois do HELLO)
 *   2) anunciarEntrada()  - depois do REGISTERED, apresenta o cliente aos outros (PEER_INFO)
 *
 * anunciarEntrada() e remover() sao synchronized no MESMO cadeado. Isso serializa as
 * entradas e saidas, e garante que:
 *   - cada par de clientes se conhece exatamente uma vez (sem faltar, sem duplicar);
 *   - ninguem recebe o PEER_LEFT de alguem antes do PEER_INFO dele.
 *
 * Ordem dos cadeados: primeiro o do Router, depois o da Session (dentro de enviarAdmin).
 * Nunca o contrario, para nao dar deadlock.
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

    /**
     * Apresenta o cliente novo aos que ja estao online e vice-versa:
     * cada lado recebe um PEER_INFO (client_id | pk | salt) do outro.
     * So conta quem ja foi anunciado; assim, dois clientes entrando juntos
     * se conhecem uma unica vez, na vez de quem anunciar por ultimo.
     */
    public synchronized void anunciarEntrada(Session nova) {
        int avisados = 0;
        for (Session outra : sessoes.values()) {
            if (outra == nova || !outra.anunciada()) {
                continue;
            }
            enviarPeerInfo(outra, nova); // a outra sessao fica sabendo da nova
            enviarPeerInfo(nova, outra); // e a nova fica sabendo da outra
            avisados++;
        }
        nova.marcarAnunciada();
        if (avisados > 0) {
            Log.info("entrada anunciada: " + nova.uuid() + " <-> " + avisados + " cliente(s)");
        }
    }

    /**
     * Remove so se a sessao registrada for ESTA (nao derruba outra com o mesmo id).
     * Se ela ja tinha sido anunciada, avisa os outros com PEER_LEFT.
     */
    public synchronized void remover(Session sessao) {
        boolean removida = sessoes.remove(sessao.uuid(), sessao);
        if (!removida || !sessao.anunciada()) {
            return;
        }
        for (Session outra : sessoes.values()) {
            if (outra.anunciada()) {
                enviarPeerLeft(outra, sessao);
            }
        }
    }

    public Session buscar(UUID id) {
        return sessoes.get(id);
    }

    public int total() {
        return sessoes.size();
    }

    // ------------------------------------------------------------------

    /** PEER_INFO: seq(8) | client_id(16) | pk(32) | salt(16). O seq e posto por enviarAdmin. */
    private static void enviarPeerInfo(Session destino, Session sobre) {
        try {
            destino.enviarAdmin(Types.PEER_INFO, sobre.clientId(), sobre.chavePublica(), sobre.salt());
        } catch (IOException e) {
            // o destino provavelmente caiu; a thread dele limpa a sessao ao notar
            Log.warn("falha ao avisar " + destino.uuid() + " sobre " + sobre.uuid() + ": " + e.getMessage());
        }
    }

    /** PEER_LEFT: seq(8) | client_id(16). */
    private static void enviarPeerLeft(Session destino, Session quemSaiu) {
        try {
            destino.enviarAdmin(Types.PEER_LEFT, quemSaiu.clientId());
        } catch (IOException e) {
            Log.warn("falha ao avisar " + destino.uuid() + " da saida de " + quemSaiu.uuid()
                    + ": " + e.getMessage());
        }
    }
}