package br.ufc.seginfo.server;

import br.ufc.seginfo.common.Certs;
import br.ufc.seginfo.common.Log;
import br.ufc.seginfo.common.Types;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Liga o servidor.
 *
 * Uso: ServerMain [porta] [caminho do server.p12] [senha]
 * Padroes: 5000, certs/server.p12, e a senha da variavel de ambiente SERVER_P12_PASSWORD
 * (ou "changeit" se ela nao existir).
 */
public class ServerMain {

    public static void main(String[] args) {
        Log.setTag("SERVER");

        try {
            int porta = args.length > 0 ? Integer.parseInt(args[0]) : Types.PORT;
            Path p12 = Path.of(args.length > 1 ? args[1] : "certs/server.p12");
            String senhaEnv = System.getenv("SERVER_P12_PASSWORD");
            char[] senha = (args.length > 2 ? args[2] : (senhaEnv != null ? senhaEnv : "changeit"))
                    .toCharArray();

            if (!Files.exists(p12)) {
                Log.error("keystore nao encontrado: " + p12.toAbsolutePath());
                Log.error("gere o certificado antes (veja as instrucoes da etapa 3)");
                System.exit(1);
            }

            Certs.Identidade identidade = Certs.carregarIdentidade(p12, senha);
            Log.info("certificado carregado: " + identidade.certificado().getSubjectX500Principal());

            new Server(identidade, porta).rodar();
        } catch (Exception e) {
            Log.error("falha ao iniciar o servidor: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            System.exit(1);
        }
    }
}