# Sistema de Mensageria Segura Multi-Cliente

Trabalho Prático 3 de Segurança da Informação (prof. Michel Sales).

Chat multi-cliente com criptografia **ponta a ponta (E2E)**. O servidor funciona apenas como
*relay*: ele encaminha os bytes e **não consegue decifrar** nenhuma mensagem.

## Garantias de segurança

| Garantia | Mecanismo |
|---|---|
| Confidencialidade | AES-128-GCM (AEAD) |
| Integridade | Tag de autenticação do AES-GCM (16 bytes) |
| Autenticidade do servidor | Certificado RSA autoassinado **pinado** no cliente + assinatura RSA-PSS (SHA-256) sobre o handshake |
| Sigilo perfeito (forward secrecy) | Chaves efêmeras X25519 (ECDHE); o segredo `Z` é descartado após derivar as chaves |
| Anti-replay | `seq_no` monotônico por direção, conferido só depois de validar a tag |
| Derivação de chaves | HKDF-SHA256 (RFC 5869), rótulos `A2B` e `B2A`, 16 bytes cada |

## Requisitos

- **JDK 25** (Temurin ou outro). Compila e roda também no 21 e no 26.
- Nenhuma dependência externa. O build é Maven (o IntelliJ já traz um Maven embutido).
- O `keytool`, que vem junto com o JDK, para gerar o certificado.

## Estrutura

```
src/main/java/br/ufc/seginfo/
├── common/    Types, Frames, Log, CryptoUtil, E2EFrame, Ids, Certs
├── server/    ServerMain, Server, Session, Router
└── client/    ClientMain, Handshake, Peer, PeerTable
src/test/java/br/ufc/seginfo/    TesteEtapa1 ... TesteEtapa6, TesteLimites
certs/         server.p12 (chave privada) e server.crt (certificado)  -> NAO vai para o Git
docs/          decisoes-projeto-tp3.txt
```

Os testes são programas com `main`. Se ainda estiverem dentro de `src/main`, tudo bem: funcionam do mesmo jeito.

| Classe | Papel |
|---|---|
| `Types` | constantes do protocolo (tipos de frame, tamanhos, limites, códigos de erro) |
| `Frames` | enquadramento no TCP: `[len 4B][type 1B][payload]`, com limite de tamanho |
| `Log` | único ponto de log; só aceita texto, e gera fingerprints de chaves |
| `CryptoUtil` | X25519, HKDF, AES-GCM, RSA-PSS, hash do handshake |
| `E2EFrame` | formato do frame cifrado e o AAD |
| `Certs` | carrega o `server.p12` (servidor) e o `server.crt` (cliente) |
| `Server` | aceita conexões (uma virtual thread por cliente) e faz o handshake |
| `Session` | ficha de um cliente conectado: id, chave pública, salt, contadores |
| `Router` | quem está online, avisos de entrada e saída, encaminhamento dos frames E2E |
| `Handshake` | lado do cliente: valida o certificado pinado e a assinatura |
| `Peer` | um contato: chaves AES derivadas, contadores, `cifrar` e `decifrar` |
| `PeerTable` | lista de contatos do cliente |
| `ClientMain` | terminal do cliente e comandos |

## Como rodar

### 1. Gerar o certificado do servidor (uma única vez)

A pasta `certs/` não vai para o Git, então crie-a e gere o par. Na raiz do projeto:

**Linux / macOS**

```bash
mkdir -p certs
keytool -genkeypair -alias server -keyalg RSA -keysize 2048 -validity 365 \
  -dname "CN=localhost" -keystore certs/server.p12 -storetype PKCS12 \
  -storepass changeit -keypass changeit
keytool -exportcert -alias server -keystore certs/server.p12 \
  -storepass changeit -rfc -file certs/server.crt
```

**Windows (PowerShell)**: se o `keytool` não for reconhecido, ele está dentro do JDK:

```powershell
New-Item -ItemType Directory -Force certs | Out-Null
$kt = (Get-ChildItem "$env:USERPROFILE\.jdks" -Recurse -Filter keytool.exe | Select-Object -First 1).FullName
& $kt -genkeypair -alias server -keyalg RSA -keysize 2048 -validity 365 -dname "CN=localhost" -keystore certs/server.p12 -storetype PKCS12 -storepass changeit -keypass changeit
& $kt -exportcert -alias server -keystore certs/server.p12 -storepass changeit -rfc -file certs/server.crt
```

- `server.p12` é a **chave privada**: fica só no servidor e nunca é versionada.
- `server.crt` é público: é o certificado que o cliente **pina**. Cliente e servidor precisam usar
  o mesmo par; se alguém gerar um par novo, o cliente recusa o servidor (`certificado do servidor
  nao confere com o pinado`).

### 2. Servidor

No IntelliJ, rode o `main` de `ServerMain`. Pela linha de comando (com Maven instalado):

```bash
mvn compile
java -cp target/classes br.ufc.seginfo.server.ServerMain [porta] [caminho do p12] [senha]
```

Padrões: porta `5000`, `certs/server.p12` e senha `changeit` (ou a variável de ambiente
`SERVER_P12_PASSWORD`).

### 3. Clientes

Rode o `main` de `ClientMain` uma vez por cliente. No IntelliJ, ative **Allow multiple instances**
na configuração de execução. Pela linha de comando:

```bash
java -cp target/classes br.ufc.seginfo.client.ClientMain [host] [porta] [caminho do server.crt]
```

Padrões: `localhost`, `5000` e `certs/server.crt`.

### Rodar pelo terminal do IntelliJ (Windows)

Alternativa que não exige configurar nada: na raiz do projeto, com o projeto já compilado
(`Ctrl+F9`). Use um terminal por processo (o **+** no topo do Terminal abre outra aba).

```powershell
$java = (Get-ChildItem "$env:USERPROFILE\.jdks" -Recurse -Filter java.exe | Select-Object -First 1).FullName
& $java -cp target/classes br.ufc.seginfo.server.ServerMain     # servidor (uma aba)
& $java -cp target/classes br.ufc.seginfo.client.ClientMain     # cada cliente, em uma aba nova
```

Suba o servidor primeiro. Os comandos do cliente são digitados na aba daquele cliente.

## Comandos do cliente

| Comando | O que faz |
|---|---|
| `/peers` | lista quem está online, com o fingerprint da chave de cada um |
| `/send <início do id> <texto>` | envia uma mensagem cifrada (mínimo 4 caracteres do id) |
| `/sair` | encerra o cliente |
| `/tamper <início do id> <texto>` | **teste**: inverte 1 bit do texto cifrado antes de enviar |
| `/replay` | **teste**: reenvia o último frame válido |
| `/badframe` | **teste**: manda um tamanho de frame absurdo |

> **Atenção:** os sinais `<` e `>` indicam onde colocar o seu valor e **não devem ser digitados**.
> Escreva `/send 94af oi, tudo bem?`, e não `/send <94af> <oi, tudo bem?>`.

Exemplo: `/peers` mostra o id `94af17f7-...`, e então `/send 94af oi, tudo bem?` envia a mensagem.
A mensagem aparece no terminal do **destinatário**; no terminal de quem envia só aparece a confirmação.

## Protocolo em resumo

Todo frame no TCP: `[len 4B big-endian][type 1B][payload]`, onde `len` é o tamanho de
`type + payload` (máximo 8192).

| Tipo | Nome | Sentido | Payload |
|---|---|---|---|
| `0x01` | HELLO | cliente → servidor | `client_id(16) \| pk(32)` |
| `0x02` | SERVER_HELLO | servidor → cliente | `salt(16) \| certLen(2) \| cert \| sigLen(2) \| assinatura` |
| `0x03` | REGISTERED | servidor → cliente | `seq(8)` |
| `0x04` | PEER_INFO | servidor → cliente | `seq(8) \| client_id(16) \| pk(32) \| salt(16)` |
| `0x05` | PEER_LEFT | servidor → cliente | `seq(8) \| client_id(16)` |
| `0x06` | ERROR | servidor → cliente | `seq(8) \| código(1)` |
| `0x10` | E2E | cliente → servidor → cliente | `nonce(12) \| sender_id(16) \| recipient_id(16) \| seq_no(8) \| texto cifrado + tag(16)` |

**Handshake:** o cliente envia `client_id` e a chave pública X25519. O servidor responde com um
salt, o certificado e uma assinatura RSA-PSS sobre
`SHA256(chave pública RSA | pk do cliente | client_id | salt)`. O cliente só continua se o certificado
for idêntico ao pinado e a assinatura for válida.

**Chaves E2E:** `Z = ECDH(minha sk, pk do peer)`, `PRK = HKDF-Extract(salt, Z)` e
`Key_A2B`, `Key_B2A = HKDF-Expand(PRK, "A2B" / "B2A", 16)`. O "A" é o `client_id` menor (bytes sem
sinal), e o salt do par é o do A.

**Nonce:** `IV_base (4 bytes aleatórios por direção) || seq_no (8 bytes, big-endian)`.
**AAD:** `sender_id | recipient_id | seq_no`.

**Conferências do receptor, em ordem:** destinatário e remetente certos, nonce coerente com o
cabeçalho, `IV_base` igual ao fixado, tag do GCM válida e `seq_no` maior que o último aceito. O estado só
muda se todas passarem.

**O servidor confere:** tamanho do frame, `sender_id` igual ao dono da conexão e destinatário
online. Ele não vê chaves nem conteúdo, e não confere o `seq_no`.

## Códigos de erro

| Código | Nome | Quando |
|---|---|---|
| `0x01` | `ERR_ID_IN_USE` | já existe um cliente conectado com esse `client_id` |
| `0x02` | `ERR_SERVER_FULL` | limite de clientes atingido |
| `0x03` | `ERR_BAD_FRAME` | framing inválido; a conexão é encerrada |
| `0x04` | `ERR_BAD_HANDSHAKE` | HELLO malformado ou chave pública inválida |
| `0x05` | `ERR_RECIPIENT_OFFLINE` | destinatário não está online (a conexão continua) |

## Parâmetros

| Parâmetro | Valor |
|---|---|
| Texto máximo por mensagem | 4096 bytes |
| Payload E2E | 68 a 4164 bytes |
| Frame máximo | 8192 bytes |
| Clientes simultâneos | 100 |
| Salt | 16 bytes |
| Chave AES | 16 bytes |
| Tempo máximo do handshake | 10 s |
| Porta padrão | 5000 |

## Política de logs

O log (classe `Log`) **só aceita texto** e registra apenas eventos de conexão e desconexão,
`client_id`, tamanhos, tipos de frame, fingerprints de 8 caracteres e o motivo de cada rejeição.
**Nunca** registra chaves privadas, o segredo `Z`, salt, nonces ou conteúdo de mensagens. O texto
recebido aparece no terminal do destinatário como interação com o usuário, e não é gravado em log.

## Testes

Cada etapa tem um teste com `main`. Rode e confira a linha final
`TUDO OK - etapa N aprovada.` Eles geram os próprios certificados temporários com o `keytool`,
então não dependem da pasta `certs/`.

| Teste | O que cobre |
|---|---|
| `TesteEtapa1` | framing, tamanhos inválidos, log |
| `TesteEtapa2` | X25519, HKDF, AES-GCM e RSA-PSS, com vetores oficiais (RFC 7748, RFC 5869) |
| `TesteEtapa3` | handshake, certificado pinado, servidor falso, `client_id` repetido, reconexão |
| `TesteEtapa4` | `PEER_INFO` e `PEER_LEFT`, incluindo entradas simultâneas |
| `TesteEtapa5` | mensagens E2E, bitflip em cada bit, replay, encaminhamento sem abrir |
| `TesteEtapa6` | `ClientMain` reais: `/send`, `/tamper`, `/replay`, `/badframe` |
| `TesteLimites` | servidor cheio (o cliente 101 recebe `ERR_SERVER_FULL`) e timeout do handshake (10 s). Demora cerca de 12 s e escreve bastante log |

## Solução de problemas

| Mensagem | Causa | O que fazer |
|---|---|---|
| `keystore nao encontrado: ...certs\server.p12` | a pasta `certs/` não vai para o Git | gerar o certificado (seção "Como rodar") |
| `NoSuchFileException: certs/server.crt` | terminal fora da raiz do projeto, ou `certs/` não existe | abrir o terminal na raiz e gerar o certificado |
| `certificado do servidor nao confere com o pinado` | `server.crt` e `server.p12` são de pares diferentes | gerar de novo e usar os dois arquivos juntos |
| `ConnectException` no cliente | o servidor não está rodando | subir o `ServerMain` primeiro |
| `Address already in use` no servidor | já existe um servidor aberto | fechar o antigo |
| `nenhum contato online com id comecando por ...` | id digitado com `<` `>`, ou prefixo errado | usar `/peers` e digitar só os 4 primeiros caracteres |
| digito um comando e nada acontece | o foco não está no console daquele cliente | clicar dentro do console (ou da aba do terminal) do cliente |

## Limitações conhecidas

- As chaves públicas dos contatos chegam **pelo servidor**; um servidor malicioso poderia trocá-las
  (MITM). A mitigação é comparar o fingerprint mostrado no `/peers` por outro canal.
- As mensagens administrativas do servidor (`REGISTERED`, `PEER_INFO`, `PEER_LEFT`, `ERROR`) têm
  `seq` contra replay, mas **não têm autenticação criptográfica**, porque o enunciado não define uma
  chave entre servidor e cliente.
- O canal entre cliente e servidor é TCP simples: quem observa a rede vê quem fala com quem e o
  tamanho dos frames. O conteúdo das mensagens continua protegido pelo E2E.
- Não há login: qualquer um pode registrar um `client_id` livre.
- Um destinatário que sai com a conexão travada pode atrasar avisos de entrada e saída.
- A rotação de chaves (opcional no enunciado) não foi implementada.
- A senha do `server.p12` é `changeit` por padrão, o que serve para o trabalho, mas não para produção.
