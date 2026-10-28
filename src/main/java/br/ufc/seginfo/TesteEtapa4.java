package br.ufc.seginfo;

import br.ufc.seginfo.client.Handshake;
import br.ufc.seginfo.client.PeerTable;
import br.ufc.seginfo.common.Certs;
import br.ufc.seginfo.common.Certs.Identidade;
import br.ufc.seginfo.common.CryptoUtil;
import br.ufc.seginfo.common.Frames;
import br.ufc.seginfo.common.Ids;
import br.ufc.seginfo.common.Log;
import br.ufc.seginfo.common.Types;
import br.ufc.seginfo.server.Server;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;

/**
 * Teste integrado da Etapa 4: varios clientes de verdade conectam num servidor de verdade
 * e conferimos quem recebe PEER_INFO e PEER_LEFT. Gera o proprio certificado temporario.
 * Pode apagar quando a etapa estiver aprovada.
 */
public class TesteEtapa4 {

    static int falhas = 0;
    static final List<Socket> abertos = Collections.synchronizedList(new ArrayList<>());

    static void check(String nome, boolean ok) {
        System.out.println((ok ? "[OK]     " : "[FALHOU] ") + nome);
        if (!ok) {
            falhas++;
        }
    }

    // ---------- certificado temporario via keytool ----------

    static Identidade gerarIdentidade(Path dir, String nome) throws Exception {
        Path p12 = dir.resolve(nome + ".p12");
        String keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
        executar(keytool, "-genkeypair", "-alias", "server", "-keyalg", "RSA", "-keysize", "2048",
                "-validity", "30", "-dname", "CN=" + nome, "-keystore", p12.toString(),
                "-storetype", "PKCS12", "-storepass", "changeit", "-keypass", "changeit");
        executar(keytool, "-exportcert", "-alias", "server", "-keystore", p12.toString(),
                "-storepass", "changeit", "-rfc", "-file", dir.resolve(nome + ".crt").toString());
        return Certs.carregarIdentidade(p12, "changeit".toCharArray());
    }

    static void executar(String... cmd) throws Exception {
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        String saida = new String(p.getInputStream().readAllBytes());
        if (p.waitFor() != 0) {
            throw new IllegalStateException("comando falhou: " + String.join(" ", cmd) + "\n" + saida);
        }
    }

    // ---------- cliente de teste ----------

    record Cliente(byte[] id, byte[] pk, Socket socket, DataInputStream in, DataOutputStream out,
                   Handshake.Resultado r) {
        UUID uuid() {
            return Ids.paraUuid(id);
        }
    }

    /** Um aviso do servidor (PEER_INFO ou PEER_LEFT), ja decodificado. */
    record Evento(byte tipo, long seq, UUID id, byte[] pk, byte[] salt) {
    }

    static Cliente conectar(int porta, byte[] id, X509Certificate pinado) throws Exception {
        byte[] pk = CryptoUtil.chavePublicaRaw(CryptoUtil.gerarParX25519().getPublic());
        Socket s = new Socket("localhost", porta);
        s.setSoTimeout(5000);
        abertos.add(s);
        DataInputStream in = new DataInputStream(new BufferedInputStream(s.getInputStream()));
        DataOutputStream out = new DataOutputStream(s.getOutputStream());
        Handshake.Resultado r = Handshake.executar(in, out, id, pk, pinado);
        return new Cliente(id, pk, s, in, out, r);
    }

    /** Proximo aviso do servidor, ou null se nada chegar em 'ms' milissegundos. */
    static Evento proximo(Cliente c, int ms) throws IOException {
        c.socket().setSoTimeout(ms);
        try {
            Frames.Frame f = Frames.read(c.in());
            long seq = ByteBuffer.wrap(f.payload()).getLong();
            if (f.type() == Types.PEER_INFO) {
                PeerTable.PeerInfo p = PeerTable.parsearPeerInfo(f.payload());
                return new Evento(f.type(), seq, p.uuid(), p.chavePublica(), p.salt());
            }
            if (f.type() == Types.PEER_LEFT) {
                return new Evento(f.type(), seq, PeerTable.parsearPeerLeft(f.payload()), null, null);
            }
            return new Evento(f.type(), seq, null, null, null); // qualquer outra coisa
        } catch (SocketTimeoutException e) {
            return null;
        }
    }

    /** Le tudo o que chegar, parando quando ficar 'ms' sem receber nada. */
    static List<Evento> drenar(Cliente c, int ms) throws IOException {
        List<Evento> eventos = new ArrayList<>();
        Evento e;
        while ((e = proximo(c, ms)) != null) {
            eventos.add(e);
        }
        return eventos;
    }

    static Set<UUID> ids(List<Evento> eventos) {
        Set<UUID> s = new HashSet<>();
        for (Evento e : eventos) {
            s.add(e.id());
        }
        return s;
    }

    static boolean todosDoTipo(List<Evento> eventos, byte tipo) {
        for (Evento e : eventos) {
            if (e.tipo() != tipo) {
                return false;
            }
        }
        return true;
    }

    /** Cada PEER_INFO bate com a chave publica e o salt reais do cliente descrito? */
    static boolean infosConferem(List<Evento> eventos, Map<UUID, Cliente> reais) {
        for (Evento e : eventos) {
            Cliente real = reais.get(e.id());
            if (real == null || !Arrays.equals(e.pk(), real.pk()) || !Arrays.equals(e.salt(), real.r().salt())) {
                return false;
            }
        }
        return true;
    }

    static boolean esperarTotal(Server s, int esperado) throws InterruptedException {
        for (int i = 0; i < 60; i++) {
            if (s.clientesConectados() == esperado) {
                return true;
            }
            Thread.sleep(50);
        }
        return false;
    }

    static Server subir(Identidade id) throws Exception {
        Server s = new Server(id, 0);
        Thread t = new Thread(s::rodar);
        t.setDaemon(true);
        t.start();
        return s;
    }

    public static void main(String[] args) throws Exception {
        Log.setTag("TESTE");

        Path tmp = Files.createTempDirectory("tp3-certs");
        Identidade real = gerarIdentidade(tmp, "servidor-real");
        X509Certificate crt = Certs.carregarCertificado(tmp.resolve("servidor-real.crt"));

        Server servidor = subir(real);
        int porta = servidor.porta();

        // ------------------------------------------------------------------
        System.out.println("=== Entradas ===");

        Cliente a = conectar(porta, Ids.novoClientId(), crt);
        check("A sozinho nao recebe nada", proximo(a, 500) == null);

        Cliente b = conectar(porta, Ids.novoClientId(), crt);
        List<Evento> eb = drenar(b, 500);
        List<Evento> ea = drenar(a, 500);
        Map<UUID, Cliente> reais = new HashMap<>();
        reais.put(a.uuid(), a);
        reais.put(b.uuid(), b);

        check("B recebe exatamente 1 PEER_INFO, sobre A",
                eb.size() == 1 && todosDoTipo(eb, Types.PEER_INFO) && ids(eb).equals(Set.of(a.uuid())));
        check("A recebe exatamente 1 PEER_INFO, sobre B",
                ea.size() == 1 && todosDoTipo(ea, Types.PEER_INFO) && ids(ea).equals(Set.of(b.uuid())));
        check("chave publica e salt anunciados sao os reais (o salt do handshake)",
                infosConferem(eb, reais) && infosConferem(ea, reais));
        check("seq administrativo continua de onde o REGISTERED parou (seq 1)",
                eb.get(0).seq() == 1 && ea.get(0).seq() == 1);

        Cliente c = conectar(porta, Ids.novoClientId(), crt);
        reais.put(c.uuid(), c);
        List<Evento> ec = drenar(c, 500);
        ea = drenar(a, 500);
        eb = drenar(b, 500);

        check("C recebe os 2 que ja estavam (A e B), sem repetir",
                ec.size() == 2 && todosDoTipo(ec, Types.PEER_INFO) && ids(ec).equals(Set.of(a.uuid(), b.uuid())));
        check("A recebe so o PEER_INFO de C (nada duplicado)",
                ea.size() == 1 && ids(ea).equals(Set.of(c.uuid())));
        check("B recebe so o PEER_INFO de C (nada duplicado)",
                eb.size() == 1 && ids(eb).equals(Set.of(c.uuid())));
        check("chaves e salts anunciados de C, A e B conferem",
                infosConferem(ec, reais) && infosConferem(ea, reais) && infosConferem(eb, reais));
        check("seq dos avisos: C recebe 1 e 2; A e B recebem 2",
                ec.get(0).seq() == 1 && ec.get(1).seq() == 2 && ea.get(0).seq() == 2 && eb.get(0).seq() == 2);

        // ------------------------------------------------------------------
        System.out.println();
        System.out.println("=== Saida ===");

        UUID idB = b.uuid();
        byte[] chaveAntigaB = b.pk();
        byte[] saltAntigoB = b.r().salt();
        b.socket().close();

        ea = drenar(a, 700);
        ec = drenar(c, 700);
        check("A recebe exatamente 1 PEER_LEFT, de B",
                ea.size() == 1 && ea.get(0).tipo() == Types.PEER_LEFT && ea.get(0).id().equals(idB));
        check("C recebe exatamente 1 PEER_LEFT, de B",
                ec.size() == 1 && ec.get(0).tipo() == Types.PEER_LEFT && ec.get(0).id().equals(idB));
        check("seq do PEER_LEFT segue a contagem (3)", ea.get(0).seq() == 3 && ec.get(0).seq() == 3);
        check("servidor tem 2 online", esperarTotal(servidor, 2));

        // ------------------------------------------------------------------
        System.out.println();
        System.out.println("=== Reconexao com o mesmo client_id ===");

        Cliente b2 = conectar(porta, b.id(), crt);
        reais.put(b2.uuid(), b2); // agora o "B real" e a nova conexao
        List<Evento> eb2 = drenar(b2, 500);
        ea = drenar(a, 500);
        ec = drenar(c, 500);

        check("B reconectado recebe A e C",
                eb2.size() == 2 && ids(eb2).equals(Set.of(a.uuid(), c.uuid())));
        check("A e C recebem o PEER_INFO de B de novo",
                ea.size() == 1 && ea.get(0).id().equals(idB) && ec.size() == 1 && ec.get(0).id().equals(idB));
        check("o PEER_INFO traz a chave NOVA de B",
                Arrays.equals(ea.get(0).pk(), b2.pk()) && !Arrays.equals(ea.get(0).pk(), chaveAntigaB));
        check("o PEER_INFO traz o salt NOVO de B",
                Arrays.equals(ea.get(0).salt(), b2.r().salt()) && !Arrays.equals(ea.get(0).salt(), saltAntigoB));

        // ------------------------------------------------------------------
        System.out.println();
        System.out.println("=== Cliente derrubado por framing invalido ===");

        UUID idC = c.uuid();
        Frames.writeRawLength(c.out(), Integer.MAX_VALUE); // o que o /badframe faz
        try {
            drenar(c, 500); // C recebe o ERROR e depois o servidor fecha
        } catch (IOException esperado) {
            // fim da conexao
        }
        ea = drenar(a, 700);
        eb2 = drenar(b2, 700);
        check("A e B recebem PEER_LEFT de C",
                ea.size() == 1 && ea.get(0).tipo() == Types.PEER_LEFT && ea.get(0).id().equals(idC)
                        && eb2.size() == 1 && eb2.get(0).tipo() == Types.PEER_LEFT && eb2.get(0).id().equals(idC));
        check("servidor tem 2 online (A e B)", esperarTotal(servidor, 2));

        // ------------------------------------------------------------------
        System.out.println();
        System.out.println("=== Entradas simultaneas (corrida) ===");

        boolean todasRodadasOk = true;
        int rodadas = 3;
        int n = 6;
        for (int rodada = 1; rodada <= rodadas; rodada++) {
            Server s2 = subir(real);
            Cliente[] cs = new Cliente[n];
            Thread[] ts = new Thread[n];
            CountDownLatch largada = new CountDownLatch(1);
            for (int i = 0; i < n; i++) {
                final int idx = i;
                ts[i] = new Thread(() -> {
                    try {
                        largada.await();
                        cs[idx] = conectar(s2.porta(), Ids.novoClientId(), crt);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                });
                ts[i].start();
            }
            largada.countDown(); // todos tentam entrar ao mesmo tempo
            for (Thread t : ts) {
                t.join();
            }

            boolean ok = true;
            Map<UUID, Cliente> todos = new HashMap<>();
            for (Cliente cl : cs) {
                if (cl == null) {
                    ok = false;
                } else {
                    todos.put(cl.uuid(), cl);
                }
            }
            if (ok) {
                for (Cliente cl : cs) {
                    List<Evento> recebidos = drenar(cl, 700);
                    Set<UUID> esperados = new HashSet<>(todos.keySet());
                    esperados.remove(cl.uuid()); // todo mundo, menos eu

                    boolean certo = recebidos.size() == n - 1                       // nem falta, nem sobra
                            && todosDoTipo(recebidos, Types.PEER_INFO)
                            && ids(recebidos).equals(esperados)                     // sem duplicado, sem eu mesmo
                            && infosConferem(recebidos, todos);                     // chaves e salts reais
                    for (int i = 0; i < recebidos.size(); i++) {
                        if (recebidos.get(i).seq() != i + 1) {                      // seq 1..n-1, em ordem
                            certo = false;
                        }
                    }
                    ok &= certo;
                }
            }
            System.out.println("  rodada " + rodada + ": " + (ok ? "ok" : "FALHOU"));
            todasRodadasOk &= ok;
            for (Cliente cl : cs) {
                if (cl != null) {
                    cl.socket().close();
                }
            }
            s2.parar();
        }
        check(n + " clientes entrando juntos, " + rodadas
                + " rodadas: todos se conhecem exatamente 1 vez", todasRodadasOk);

        for (Socket s : abertos) {
            s.close();
        }
        servidor.parar();

        System.out.println();
        if (falhas == 0) {
            System.out.println("TUDO OK - etapa 4 aprovada.");
        } else {
            System.out.println(falhas + " teste(s) falharam.");
            System.exit(1);
        }
    }
}