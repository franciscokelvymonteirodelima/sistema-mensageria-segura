package br.ufc.seginfo;

import br.ufc.seginfo.common.Certs;
import br.ufc.seginfo.common.Certs.Identidade;
import br.ufc.seginfo.common.Log;
import br.ufc.seginfo.server.Server;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Teste da Etapa 6: usa o ClientMain DE VERDADE (um processo por cliente) e digita neles
 * os comandos da demonstracao: /send, /tamper, /replay e /badframe.
 * E o ensaio automatico da apresentacao. Pode apagar quando a etapa estiver aprovada.
 */
public class TesteEtapa6 {

    static int falhas = 0;
    static final int ESPERA_MS = 15_000;

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

    // ---------- um ClientMain rodando como processo ----------

    static class Cliente {
        final Process processo;
        final PrintWriter teclado;
        final StringBuffer tela = new StringBuffer(); // tudo o que o cliente imprimiu

        Cliente(int porta, Path crt) throws IOException {
            String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
            ProcessBuilder pb = new ProcessBuilder(java, "-cp", System.getProperty("java.class.path"),
                    "br.ufc.seginfo.client.ClientMain", "localhost", String.valueOf(porta), crt.toString());
            pb.redirectErrorStream(true);
            processo = pb.start();
            teclado = new PrintWriter(
                    new OutputStreamWriter(processo.getOutputStream(), StandardCharsets.UTF_8), true);

            Thread leitor = new Thread(() -> {
                try (BufferedReader r = new BufferedReader(
                        new InputStreamReader(processo.getInputStream(), StandardCharsets.UTF_8))) {
                    String linha;
                    while ((linha = r.readLine()) != null) {
                        tela.append(linha).append('\n');
                    }
                } catch (IOException fim) {
                    // processo terminou
                }
            });
            leitor.setDaemon(true);
            leitor.start();
        }

        /** Digita uma linha no terminal do cliente. */
        void digitar(String linha) {
            teclado.println(linha);
        }

        int contar(String trecho) {
            String t = tela.toString();
            int n = 0;
            for (int i = t.indexOf(trecho); i >= 0; i = t.indexOf(trecho, i + trecho.length())) {
                n++;
            }
            return n;
        }

        boolean contem(String trecho) {
            return tela.indexOf(trecho) >= 0;
        }

        /** Espera o trecho aparecer 'vezes' vezes na tela do cliente. */
        boolean esperar(String trecho, int vezes) throws InterruptedException {
            long limite = System.currentTimeMillis() + ESPERA_MS;
            while (System.currentTimeMillis() < limite) {
                if (contar(trecho) >= vezes) {
                    return true;
                }
                Thread.sleep(50);
            }
            return false;
        }

        boolean esperar(String trecho) throws InterruptedException {
            return esperar(trecho, 1);
        }

        boolean terminou() throws InterruptedException {
            return processo.waitFor(ESPERA_MS, TimeUnit.MILLISECONDS);
        }

        String idCompleto() {
            Matcher m = Pattern.compile("meu client_id=([0-9a-f-]{36})").matcher(tela);
            return m.find() ? m.group(1) : null;
        }

        void encerrar() {
            teclado.println("/sair");
            processo.destroy();
        }
    }

    static boolean esperarTotal(Server s, int esperado) throws InterruptedException {
        for (int i = 0; i < 100; i++) {
            if (s.clientesConectados() == esperado) {
                return true;
            }
            Thread.sleep(50);
        }
        return false;
    }

    public static void main(String[] args) throws Exception {
        Log.setTag("TESTE");

        Path tmp = Files.createTempDirectory("tp3-demo");
        Identidade identidade = gerarIdentidade(tmp, "servidor");
        Path crt = tmp.resolve("servidor.crt");

        Server servidor = new Server(identidade, 0);
        Thread t = new Thread(servidor::rodar);
        t.setDaemon(true);
        t.start();
        int porta = servidor.porta();

        Cliente a = new Cliente(porta, crt);
        Cliente b = new Cliente(porta, crt);

        // ------------------------------------------------------------------
        System.out.println("=== Preparacao: dois ClientMain de verdade ===");
        check("A fez o handshake", a.esperar("handshake concluido"));
        check("B fez o handshake", b.esperar("handshake concluido"));
        check("A viu B entrar", a.esperar("peer entrou"));
        check("B viu A entrar", b.esperar("peer entrou"));

        String idB = b.idCompleto();
        check("consegui o id do B", idB != null);
        String b8 = idB.substring(0, 8);

        // ------------------------------------------------------------------
        System.out.println();
        System.out.println("=== /send: o caminho normal ===");
        a.digitar("/send " + b8 + " mensagem normal");
        check("A confirma o envio", a.esperar("enviado para " + b8));
        check("B recebe e mostra a mensagem", b.esperar("] mensagem normal"));
        check("ate aqui B nao rejeitou nada", !b.contem("rejeitada"));

        // ------------------------------------------------------------------
        System.out.println();
        System.out.println("=== /tamper: bitflip no caminho ===");
        a.digitar("/tamper " + b8 + " mensagem adulterada");
        check("A avisa que adulterou de proposito", a.esperar("adulterando de proposito"));
        check("A confirma: enviado (ADULTERADO)", a.esperar("enviado (ADULTERADO) para " + b8));
        check("B rejeita com TAG_INVALIDA", b.esperar("rejeitada: TAG_INVALIDA"));
        check("o texto adulterado NUNCA aparece para o B", !b.contem("] mensagem adulterada"));

        a.digitar("/send " + b8 + " depois do ataque");
        check("a mensagem seguinte passa (o ataque nao travou o contador)", b.esperar("] depois do ataque"));

        // ------------------------------------------------------------------
        System.out.println();
        System.out.println("=== /replay: reenvio de frame antigo ===");
        a.digitar("/replay");
        check("A avisa que esta reenviando", a.esperar("reenviando de proposito"));
        check("B rejeita com REPLAY", b.esperar("rejeitada: REPLAY"));
        check("a mensagem repetida aparece so 1 vez no B", b.contar("] depois do ataque") == 1);

        a.digitar("/replay");
        check("de novo: 2 rejeicoes por REPLAY", b.esperar("rejeitada: REPLAY", 2));
        check("continua so 1 vez na tela do B", b.contar("] depois do ataque") == 1);

        a.digitar("/send " + b8 + " ainda funciona");
        check("depois dos ataques, a conversa normal continua", b.esperar("] ainda funciona"));

        // ------------------------------------------------------------------
        System.out.println();
        System.out.println("=== Casos de uso errado ===");
        Cliente c = new Cliente(porta, crt);
        check("C fez o handshake", c.esperar("handshake concluido"));
        c.digitar("/replay");
        check("/replay sem ter enviado nada avisa e nao quebra", c.esperar("nada para reenviar"));
        c.digitar("/tamper 00000000 teste");
        check("/tamper para id inexistente avisa", c.esperar("nenhum contato online"));

        // ------------------------------------------------------------------
        System.out.println();
        System.out.println("=== /badframe: framing invalido ===");
        check("servidor tem 3 online (A, B e C)", esperarTotal(servidor, 3));
        c.digitar("/badframe");
        check("C avisa que vai mandar o frame invalido", c.esperar("tamanho invalido de proposito"));
        check("o servidor encerra a conexao do C", c.esperar("o servidor encerrou a conexao"));
        check("o processo do C termina", c.terminou());
        check("servidor volta a ter 2 online", esperarTotal(servidor, 2));

        a.digitar("/send " + b8 + " apos o badframe");
        check("A e B nao foram afetados", b.esperar("] apos o badframe"));

        // ------------------------------------------------------------------
        a.encerrar();
        b.encerrar();
        c.encerrar();
        servidor.parar();

        System.out.println();
        if (falhas == 0) {
            System.out.println("TUDO OK - etapa 6 aprovada.");
        } else {
            System.out.println(falhas + " teste(s) falharam.");
            System.exit(1);
        }
    }
}