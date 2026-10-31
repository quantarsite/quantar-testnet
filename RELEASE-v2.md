# HYDRA-X v2: relançamento da testnet

A v2 é incompatível com a v1. Endereços, chaves, assinaturas e o estado da
testnet antiga não valem mais. Todo mundo começa do zero em `quantar-testnet-2`.

## O que mudou

- ML-DSA-87 da FIPS 204 (assinatura de 4.627 bytes) no lugar do Dilithium5
  round-3, e SLH-DSA-SHA2-256s da FIPS 205 no lugar do SPHINCS+ round-3, nos
  dois lados: quem assina (qtrc-crypto) e quem verifica (hx-mempool)
- O mempool verificava a perna SLH com SPHINCS+ round-3 enquanto o núcleo já
  assinava com FIPS 205. Isso faria toda transação real ser rejeitada. Corrigido
- Separação de domínio: toda assinatura de transação e de bloco começa com
  `QTR-HYDRAX-V2 || len(chain_id) || chain_id`. Uma assinatura da v1 ou de
  outra rede não verifica aqui
- Chain id `quantar-testnet-2`, gênesis em 2026-10-18 00:00:00 UTC
- O gênesis financiava a string `faucet_placeholder_replace_with_real_address`,
  ou seja, ninguém. Agora financia o endereço em `QTR_FAUCET_ADDRESS`
- O faucet chamava `/faucet/drip`, uma rota que o node nunca teve. Agora ele
  assina uma transação HYDRA-X de verdade com a própria chave e manda para `/tx`
- Chave persistente: `qtrc-node keygen --out <arquivo>` grava a chave (modo
  0600, não sobrescreve) e `start --key-file` usa ela. Antes o node gerava uma
  chave nova a cada reinício
- ID de transação sem maleabilidade: o ID agora é o BLAKE3 do payload
  assinado, o mesmo hash do mempool. Antes era o SHA3 do JSON inteiro, com o
  timestamp não assinado dentro, então qualquer um que repassasse a transação
  podia mudar o ID sem invalidar a assinatura
- Faucet entrega 50 QTR por pedido, com limite por endereço, por IP (1 por
  hora cada) e teto global de 100 drips por hora, ou seja, no máximo
  5.000 QTR por hora. Entradas vencidas são limpas a cada 10 minutos. Os
  cabeçalhos do nginx só são aceitos quando a conexão vem do próprio servidor
- Chave secreta guardada em buffers que se apagam ao sair da memória. Antes o
  código copiava a chave e apagava só a cópia. Limite honesto: isso apaga as
  cópias que o nosso código controla, não as que o compilador ou o código C do
  PQClean possam deixar. Para mainnet, HSM
- Versão 0.2.0 em todos os crates

- A chain agora persiste em disco. Cada bloco é gravado (e sincronizado com o
  disco) antes de ser considerado confirmado, e ao reiniciar o node verifica de
  novo as assinaturas HYDRA-X de todos os blocos e reconstrói o estado. O
  gênesis fica gravado na pasta de dados, então reiniciar sem
  `QTR_FAUCET_ADDRESS` não cria uma chain diferente por acidente
- Bloco aplica inteiro ou não aplica: antes, se a terceira transação de um
  bloco falhasse, as duas primeiras já tinham mudado os saldos
- Bloco sem a assinatura HYDRA-X do proponente é rejeitado (a v1 aceitava como
  "modo de um node só")
- Sem blocos vazios: cada bloco carrega uma assinatura de cerca de 37 KB, e um
  bloco vazio a cada 5 segundos encheria o disco em mais de 1 GB por dia. A
  altura da chain só sobe quando há transação
- As chaves de bloco no disco são big-endian; em little-endian a ordem quebra
  a partir do bloco 256

## O que ainda não mudou (não fingir que mudou)

- Transações que estavam no mempool e ainda não entraram em bloco se perdem
  num reinício. O faucet reenvia normalmente no próximo pedido
- Ainda é um node só, sem P2P

## Passo a passo no servidor (droplet 164.90.145.184)

Feito assim em 18/10/2026. O node e o faucet rodam como serviços do systemd,
presos em 127.0.0.1; só o nginx fala com a internet.

1. Backup: copie configs do nginx, `/var/www` e dados antigos para `/root/backup-v1`
2. Código nas duas pastas irmãs: `~/quantar-testnet` e `~/hx-mempool` (`git pull`)
3. Swap de 2 GB (o droplet tem 1 GB de RAM), Rust via rustup, `build-essential pkg-config libssl-dev`
4. `cargo build --release` e `install -m 755 target/release/qtrc-{node,faucet,wallet} /usr/local/bin/`
5. Chaves, uma vez só, com backup fora do servidor:
   `qtrc-node keygen --out /etc/quantar/node.key` e `--out /etc/quantar/faucet.key`
6. `/etc/quantar/node.env` com `QTR_FAUCET_ADDRESS=<endereco completo do faucet>`
7. `/etc/systemd/system/quantar-node.service`:
   `ExecStart=/usr/local/bin/qtrc-node start --rpc 127.0.0.1:8545 --data-dir /var/lib/quantar --key-file /etc/quantar/node.key`
   com `EnvironmentFile=/etc/quantar/node.env` e `Restart=on-failure`
8. `/etc/systemd/system/quantar-faucet.service`:
   `ExecStart=/usr/local/bin/qtrc-faucet --listen 127.0.0.1:8546 --node-rpc http://127.0.0.1:8545 --key-file /etc/quantar/faucet.key`
9. nginx: `deploy/nginx/quantar-rpc-limits.conf` em `/etc/nginx/conf.d/`,
   `deploy/nginx/testnet-rpc.locations` em `/etc/quantar/` incluído no server 443
   de testnet.quantarnetwork.com, e o `/api/` do faucet apontando para 127.0.0.1:8546
   com `proxy_set_header X-Real-IP $remote_addr;`
10. Confira: `curl https://testnet.quantarnetwork.com/rpc/status` e `qtrc-wallet status`

## Testes que provam a v2

- `crates/qtrc-consensus/tests/hydrax_v2.rs`: transação assinada pelo núcleo
  passa pelo mempool, entra num bloco e muda o saldo; assinatura no layout da
  v1 é rejeitada; o prefixo de domínio é idêntico nos dois repos
- `hx-mempool/tests/hydrax_v2.rs`: assinatura SLH-DSA FIPS 205 real verifica
  pela rota de produção
- Testado de ponta a ponta com os binários: keygen, node, faucet, dois drips
  seguidos com nonces 0 e 1, saldos conferidos

## v2.0.1: correções da revisão independente

Uma revisão feita por um agente separado, que não escreveu o código, achou
3 problemas graves e 4 médios. Nenhum permitia aceitar transação sem as duas
assinaturas. Todos corrigidos, com teste para cada um que foi reproduzido:

- Faucet dizia "Sent 50 QTR" e a tx sumia: durante a montagem de um bloco as
  txs ficavam fora da contagem de pendentes e o nonce era reutilizado. Agora
  contam como "em voo" até o bloco confirmar ou falhar
- A entrada confere nonce exato e saldo (contando o que já está pendente),
  com teto de 16 txs pendentes por conta e 5.000 na fila: spam sem saldo ou
  fora de ordem é recusado antes de custar uma verificação
- Blocos gravados em binário (bincode), bem menores que o JSON; blocos antigos
  em JSON continuam sendo lidos, sem reset
- Com menos de 2 GB livres o node para de aceitar transações, em vez de
  encher o disco e derrubar os outros sites do servidor
- Bloco só é aceito do proponente esperado e assinado pela chave dele (antes
  qualquer chave servia)
- Tx descartada pode ser reenviada (antes o node respondia OK e ignorava)
- RPC e faucet escutam em 127.0.0.1 por padrão; a verificação roda fora do
  runtime assíncrono
- Faucet: só confia no X-Real-IP vindo do nginx local, IPv6 agrupado por /64,
  timeout nas chamadas ao node
- Frases públicas corrigidas: o que não usa ECDSA são as assinaturas de
  transação e bloco; o HTTPS da carteira usa TLS clássico, como qualquer site

Sem taxa, transferências seguem gratuitas, então um atacante paciente ainda
consegue gerar volume. Os limites acima reduzem e contêm isso; a solução de
verdade é uma taxa mínima, que é decisão de economia do token.

## v2.0.2: taxa de 0,01 QTR por transação, queimada

- Quem envia paga o valor mais 0,01 QTR; quem recebe ganha o valor cheio.
  A taxa é queimada: sai do supply e ninguém recebe
- É regra de consenso, não um campo da transação, então o formato e as
  assinaturas não mudam e a carteira da v2.0.0 continua funcionando
- A chain que já existia continua válida: a taxa começa no primeiro bloco
  depois da atualização, e essa altura fica gravada na pasta de dados (como o
  gênesis). Uma chain nova cobra desde o bloco 1
- `/rpc/status` mostra `fee` (taxa do próximo bloco) e `burned` (total
  queimado); a carteira mostra os dois e avisa quando falta saldo para a taxa
- Com a taxa, gerar volume custa: os 50 QTR do faucet dão para 5.000
  transferências, e o faucet entrega no máximo 5.000 QTR por hora

## v2.1.0: HYDRA-X Sentinel (sem reset)

Recuperação com compromisso em hash, transferências grandes com atraso e
watchtower (crate `qtrc-sentinel`), ligado no consenso com altura de
ativação. Detalhes em `crates/qtrc-sentinel/README.md`.

Compatibilidade: transação comum continua com os mesmos bytes assinados,
hash e assinatura; blocos antigos (0x01) são lidos; blocos sem operação
Sentinel continuam sendo gravados em 0x01. O Sentinel liga no bloco
seguinte ao primeiro start do binário novo (fica gravado no data dir).

Deploy no droplet:

1. Backup: `systemctl stop quantar-node quantar-faucet` e
   `cp -a /var/lib/quantar /root/backup-quantar-$(date +%F)`
2. `cd ~/quantar-testnet && git checkout main && git pull` e `cd ~/hx-mempool && git pull`
3. `cargo build --release` e `install -m 755 target/release/qtrc-{node,faucet,wallet} /usr/local/bin/`
4. nginx: copiar `deploy/nginx/testnet-rpc.locations` para `/etc/quantar/`
   (nova rota `/rpc/vault/`, corpo até 512k), `nginx -t && systemctl reload nginx`
5. `systemctl start quantar-node quantar-faucet` e
   `journalctl -u quantar-node -n 30` mostra `sentinel_from_height`
6. Confira: `curl https://testnet.quantarnetwork.com/rpc/status` com
   `"version":"0.3.0"` e `sentinel_from_height`
7. Release `v2.1.0` no GitHub para publicar a carteira nova

Volta atrás: enquanto nenhum bloco tiver operação Sentinel, o binário
anterior roda no mesmo data dir. Depois disso, só restaurando o backup.
Release com `overflow-checks = true`: overflow aritmético para o node.

## v2.2.0: watchtower como serviço

`qtrc-watchtower` vigia contas com guardião pela RPC do node e envia o
resgate sozinho quando aparece algo hostil (transferência grande para
endereço desconhecido, roubo fatiado, fila inundada, troca de guardião não
anunciada). A decisão é o `watchtower::tick` auditado, rodado numa cópia do
cofre. Ele não guarda chave de nenhuma conta protegida: só o kit de cada
uma e uma carteira própria que paga as taxas. Comprometido, o máximo que
consegue é mandar o saldo para a carteira fria do próprio dono.

Deploy no droplet:

1. `cargo build --release` e `install -m 755 target/release/qtrc-watchtower /usr/local/bin/`
2. Carteira das taxas: `qtrc-wallet --key /etc/quantar/watchtower.key new`,
   depois `qtrc-wallet --key /etc/quantar/watchtower.key faucet`
3. `mkdir -p /etc/quantar/kits`, copie o `.kit.json` de cada conta protegida
   para lá (`chmod 600`)
4. `/etc/quantar/watchtower.json` a partir de `deploy/watchtower.example.json`
5. `cp deploy/systemd/quantar-watchtower.service /etc/systemd/system/`,
   `systemctl daemon-reload && systemctl enable --now quantar-watchtower`
6. `journalctl -u quantar-watchtower -f`

O config é relido a cada ciclo: incluir conta ou trocar kit não precisa de
restart. Depois de um `guardian rotate`, troque o kit pelo novo assim que a
rotação finalizar; até lá o watchtower avisa que está desarmado. O
`webhook` (opcional) recebe cada alerta como JSON `{"text","content"}`,
formato aceito por Slack e Discord.

## v2.3.0: state root no cabeçalho (sem reset)

Cada bloco a partir da ativação traz no cabeçalho a raiz de uma árvore
Merkle com todas as contas (saldo, nonce e hash do cofre Sentinel) e o
total queimado. O proponente calcula, e quem confirma o bloco recalcula e
recusa raiz errada, ausente ou adiantada. `qtrc-wallet proof <endereço>`
confere o saldo sem confiar no nó que respondeu: exige a assinatura HYDRA-X
do validador da testnet (fixo na carteira, ou `--validator`) no cabeçalho e
a prova Merkle da conta contra a raiz desse cabeçalho. Limite: prova o
saldo daquele bloco; um nó ainda pode responder com um bloco mais antigo
(a carteira mostra a idade do bloco). Conta vazia não tem prova e aparece
como "não verificado". É a base para vários validadores concordarem sobre
o estado.

A raiz usa uma codificação canônica e versionada do cofre Sentinel,
travada por um vetor de teste, para que mudanças futuras no formato de
armazenamento nunca alterem raízes antigas. A árvore é calculada uma vez
por bloco e as provas saem dela em O(log n), sem travar o estado do nó.

Compatibilidade: o campo só entra no JSON assinado quando existe, então os
blocos antigos mantêm bytes, hashes e assinaturas. Blocos com raiz usam o
formato 0x03; 0x01, 0x02 e JSON continuam sendo lidos (testado com blocos
gravados pela versão anterior). A raiz liga no bloco seguinte ao primeiro
start do binário novo, gravada no data dir.

Deploy no droplet:

1. Backup: `systemctl stop quantar-watchtower quantar-faucet quantar-node` e
   `cp -a /var/lib/quantar /root/backup-quantar-$(date +%F)-v2.3`
2. `cd ~/quantar-testnet && git pull && cargo build --release`
3. `install -m 755 target/release/qtrc-{node,faucet,wallet,watchtower} /usr/local/bin/`
4. `cp deploy/nginx/testnet-rpc.locations /etc/quantar/` (nova rota
   `/rpc/proof/`), `nginx -t && systemctl reload nginx`
5. `systemctl start quantar-node quantar-faucet quantar-watchtower`
6. `journalctl -u quantar-node -n 15 --no-pager` mostra `state_root_from_height`
7. Depois do primeiro bloco novo: `qtrc-wallet proof <endereço>`

Volta atrás: a partir do primeiro bloco com raiz o binário anterior não lê
mais o data dir (para com "unknown block encoding", sem corromper nada).
Voltar só restaurando o backup do passo 1.
Se voltar antes do primeiro bloco com raiz e depois reinstalar a versão
nova, o node detecta os blocos sem raiz e move a ativação para depois
deles sozinho.

## v2.3.1: o node recusa banco de dados danificado

Achado F1 do teste adversarial: com blocos grandes (assinaturas HYDRA-X), o
sled guarda os valores como blobs. Se o arquivo `snap.*` se perder depois de
uma reabertura, o banco abre vazio, sem erro, e o node achava que era uma
pasta nova: gravava outra gênese e começava uma cadeia do zero com a mesma
chave de validador.

Agora existe `<data-dir>/chain.marker`, fora do sled, com a última altura
gravada. Ele nasce junto com a gênese e sobe a cada bloco. Se o sled abrir
sem gênese ou com menos blocos do que o marker diz, o node não sobe e manda
restaurar o backup. Pastas antigas ganham o marker na primeira abertura, na
altura em que estão. Nada muda no consenso nem nos bytes dos blocos.

Deploy: os mesmos passos da v2.3.0 (backup primeiro). Depois de subir,
`cat /var/lib/quantar/chain.marker` deve mostrar a altura atual.

## v2.3.2: fila de transações indexada e com lugar para recuperação

Achados F2, F4 e F5 do teste adversarial.

- F2: cada envio, até o lixo sem chave nem saldo, refazia o hash de todas
  as transações da fila sob o lock global (62 ms com a fila cheia de
  recuperações). Agora a fila mantém índices por hash e por remetente; o
  custo de recusar lixo é o mesmo com a fila vazia ou cheia (~15 µs).
- F4: além do limite de 5.000 transações, a fila tem limite de 64 MiB.
  Antes, cheia, ela passava de 600 MB com as cópias do hx-mempool.
- F5: recuperações do Sentinel têm 64 vagas próprias, por cima dos dois
  limites, e o remetente de uma recuperação vai primeiro no bloco (todas as
  transações dele, na ordem de nonce). Um ladrão com a chave principal não
  consegue mais lotar a fila para atrasar a recuperação até o time lock
  vencer. Finalize não ganha vaga própria de propósito: quem quer finalizar
  numa conta roubada é o ladrão.

Nada muda no consenso nem nos bytes dos blocos. Deploy igual à v2.3.1.

## v2.3.3: árvore de estado atualizada, não reconstruída

Achado F3 do teste adversarial. A raiz era recalculada do zero duas vezes
por bloco (ao propor e ao confirmar) e de novo a cada bloco no replay.

- `ChainState` guarda as chaves que cada transação tocou (vêm do mesmo
  journal que faz o rollback, por onde passa toda mudança de conta e cofre).
- O node mantém a árvore do último bloco e só refaz as folhas tocadas e os
  caminhos delas. Se uma conta aparece ou some, as posições mudam e os
  níveis acima das folhas são refeitos a partir dos hashes em cache.
- O node reaproveita a árvore da própria proposta ao confirmar o bloco.
- Mesma raiz, mesmas provas: um teste roda milhares de transações
  aleatórias (todas as operações do Sentinel incluídas) e compara, bloco a
  bloco, a árvore atualizada com a reconstrução completa.

Medido por bloco com 500 contas alteradas:

| contas | antes (cada vez) | sem conta nova | com conta nova |
|---|---|---|---|
| 10 mil | 23 ms | 3 ms | 9 ms |
| 100 mil | 279 ms | 15 ms | 75 ms |
| 1 milhão | 2,9 s | 120 ms | 670 ms |

Limite honesto: com contas novas a árvore ordenada por endereço desloca
posições, e isso continua O(n). Resolver de vez pede outro formato de
compromisso (árvore esparsa por endereço), que muda a raiz e entra com
altura de ativação junto com o trabalho de múltiplos validadores. Nada muda
no consenso nesta versão.

## v2.4.0: cabeçalho cobre a transação inteira, regras fixas da rede, /block

Achados F6 e F8 do teste adversarial.

- Witness root (F6): o `merkle_root` cobre só os IDs das transações, que de
  propósito deixam de fora assinaturas e timestamps. Assim um bloco gravado
  ou repassado podia mudar sem mudar o cabeçalho. Agora o cabeçalho leva
  `witness_root`, um compromisso com todos os bytes de cada transação
  (payload, timestamp, as duas assinaturas, endereço do signatário), com
  todos os campos prefixados pelo tamanho. Vale a partir do bloco 20.
  Formato 0x04 no disco.
- Regras fixas (F8): o endereço do faucet da gênese e as alturas de
  ativação da quantar-testnet-2 (taxa 5, Sentinel 6, state root 15, witness
  root 20) estão no código (`qtrc-common/src/chain.rs`). Um servidor novo,
  em outro provedor, reconstrói exatamente a mesma cadeia sem configuração.
  Antes, uma pasta vazia ligaria todas as regras no bloco 1 e recusaria os
  blocos reais. Uma pasta que gravou alturas diferentes já usadas é recusada.
- `GET /block/:height` (e `/rpc/block/<altura>` no nginx): qualquer um pode
  baixar os blocos e refazer a cadeia, conferindo cabeçalho, assinaturas,
  state root e witness root.

Atenção: a partir do bloco 20 a carteira precisa ser a v2.4.0 para conferir
provas. Versões antigas não conhecem o campo novo, montam bytes diferentes
para a assinatura do cabeçalho e respondem "não verificado".

Deploy: os passos de sempre (backup primeiro), mais copiar
`deploy/nginx/testnet-rpc.locations` para `/etc/quantar/` e recarregar o
nginx. No log deve aparecer "Known network: activation heights fixed by the
chain parameters" e `witness_root_from_height=20`.

## v2.5.0: nó seguidor e validador histórico fixo

Primeiro passo para vários validadores (plano em três fases).

- O validador da quantar-testnet-2 (`809ae6fb…bbcbbbff`) está no código.
  Antes, com a lista de validadores vazia, um nó só aceitava blocos
  assinados pela própria chave: funcionava no droplet, e um segundo
  servidor recusaria o bloco 1. O node também se recusa a produzir blocos
  com uma chave que não é de validador.
- `qtrc-node start --follow <url>` (repetível): o nó baixa cada bloco de
  outros nós por `/block/:height`, confere tudo o que um commit confere
  (altura, hash anterior, raízes de transações e witness, assinatura HYDRA-X
  de cada transação, assinatura do validador esperado, regras do Sentinel,
  state root) e só então grava. Par mentiroso é pulado; sem par honesto, o
  seguidor para antes do bloco forjado. Seguidor não aceita transações e
  responde `role: "follower"` em `/status`.
- `deploy/systemd/quantar-follower.service` para o segundo servidor.

Num servidor novo (Ubuntu, 2 GB): instalar Rust, clonar quantar-testnet e
hx-mempool lado a lado, `cargo build --release`, instalar `qtrc-node` e
`qtrc-wallet`, criar `/var/lib/quantar`, copiar o service e
`systemctl enable --now quantar-follower`. Não precisa de chave nem de
`QTR_FAUCET_ADDRESS`: a gênese e as regras vêm do código.

## v2.6.0: anúncio de blocos entre nós (fase 2, primeira parte)

- O validador avisa os seguidores logo depois de cada bloco
  (`--announce-to http://IP:9545`, repetível). O aviso é o cabeçalho do
  bloco com a assinatura HYDRA-X do validador que o bloco já carrega:
  nada novo é assinado, e o validador não gasta CPU a mais.
- O seguidor escuta com `--p2p 0.0.0.0:9545`. Só uma rota, corpo de até
  256 KB, duas verificações por vez, timeout de 15 s. Confere primeiro o
  barato (altura, proponente esperado) e só depois a assinatura. Aviso
  válido acorda a sincronização na hora; o bloco em si continua vindo por
  `/block/:height` e passa por todas as verificações do commit. Aviso
  falso ou adulterado é recusado e não muda nada.
- Sem aviso (porta fechada, validador antigo), o seguidor continua
  perguntando a cada 5 s, como antes.
- Sem `--key-file`, o nó usa `<data-dir>/node.key`, criado na primeira
  vez. O endereço do seguidor não muda mais a cada reinício.
- `ConsensusEngine::verify_header` e `subscribe_commits`: a base para os
  votos da fase 3.

Deploy no seguidor: backup, copiar o binário, atualizar o service (porta
9545), `ufw allow 9545/tcp`, reiniciar. No validador: backup, binário novo,
`--announce-to http://207.154.219.21:9545` no ExecStart, reiniciar.

Atenção no validador: parar o `quantar-node` para também o faucet e o
watchtower, e eles não voltam sozinhos. Depois de ligar o node:
`systemctl start quantar-faucet quantar-watchtower` e conferir com
`systemctl is-active quantar-node quantar-faucet quantar-watchtower`.

## v2.7.0: vários validadores votando (fase 3, rede de teste local)

Ainda não muda a rede no ar: as regras novas só valem com `--bft-config`,
que a quantar-testnet-2 recusa (as regras dela vêm do código).

- `qtrc-bft`: o Tendermint do Malachite (núcleo 0.8.2) com votos e
  propostas assinados em HYDRA-X. Modo `ProposalAndParts`: no
  `ProposalOnly` o Malachite 0.8.2 aceita qualquer proposta como válida.
- Bloco decidido só com prova de commit: precommits de validadores com
  mais de 2/3 do poder de voto, cada um verificado. Seguidor e quem
  refaz a cadeia conferem a mesma prova. Formato 0x05 no disco.
- Proteção contra voto duplo gravada no disco antes de cada assinatura
  (`<data-dir>/bft-sign-state`), vale depois de reiniciar.
- Node: `--bft-config arquivo.json` com `bft_from_height` e a lista de
  validadores (`address`, `p2p`). Validador precisa de `--p2p`. Votos e
  propostas (com o bloco) vão por HTTP para `/p2p/v1/consensus`;
  transações recebidas de clientes são repassadas aos outros validadores;
  quem ficou para trás busca os blocos com prova em `/p2p/v1/block/:h`.
- Altura nova só começa quando há transação (sem blocos vazios).
- `deploy/devnet/run-local.sh`: 4 validadores na mesma máquina.

Testado com 4 processos locais: blocos decididos na rodada 0; com um
validador desligado os outros três seguem (a altura em que ele era o
proponente fechou na rodada 1); ao religar ele busca os blocos que
perdeu e volta a votar; um seguidor refaz a cadeia conferindo as provas;
cinco transações seguidas chegam iguais aos quatro.

Limites no p2p: só os endereços IP dos validadores (resolvidos das URLs
`p2p` da configuração, de novo a cada 5 minutos) passam da porta, antes de
qualquer byte do corpo ser lido; cada um tem até 50 pedidos por segundo
(rajada de 200); a fila do consenso tem 4.096 lugares e recusa o excesso
com 503 (os timers sempre entram).

Falta antes de ativar numa rede pública: servidores em provedores
diferentes e revisão independente.

## v2.8.0: mudança de limites do Sentinel (sem reset)

- `UpdatePolicy`: o dono muda `delay_blocks` e `allowance_per_window` da
  própria conta. Apertar (limite menor ou igual e atraso maior ou igual)
  vale no bloco seguinte. Qualquer outra mudança, inclusive mista, espera
  o atraso atual em público, com o limite antigo valendo durante a espera;
  a recuperação cancela. Limite novo abaixo do que já saiu na janela é
  recusado (`AllowanceInUse`).
- Ativa no bloco 40 da quantar-testnet-2 (`POLICY_UPDATE_TESTNET2`).
  Antes dele a operação é recusada; blocos antigos refazem igual.
- O watchtower recupera a conta diante de qualquer mudança de limites na
  fila que não seja a `expected_policy` da config.
- Carteira: `qtrc-wallet guardian policy --delay N --allowance X`; o
  `vault` mostra a mudança pendente. `/status` mostra
  `policy_update_from_height`.
- Vaults que nunca pedem mudança mantêm a mesma codificação no state root
  (vetor v1 inalterado; vetor novo para a mudança pendente).

Esta versão também leva ao servidor o que entrou depois da v2.6.0 (BFT da
v2.7.0 e recuperação v3), tudo desligado na rede no ar: BFT só vale com
`--bft-config`, que a quantar-testnet-2 recusa, e a recuperação v3 segue
em `u64::MAX`. Os blocos continuam gravados no formato 0x04.

Deploy, seguidor primeiro (207.154.219.21), depois validador
(164.90.145.184). Os dois antes do bloco 40.

1. Backup: `systemctl stop <serviços>` e
   `cp -a /var/lib/quantar /root/backup-quantar-$(date +%F)-v2.7`
2. `cd ~/hx-mempool && git pull`, `cd ~/quantar-testnet && git pull && cargo build --release`
3. Seguidor: `install -m 755 target/release/qtrc-{node,wallet} /usr/local/bin/`.
   Validador: `install -m 755 target/release/qtrc-{node,faucet,wallet,watchtower} /usr/local/bin/`
4. Iniciar os serviços e conferir `systemctl is-active`.
5. `/status` mostra `version 0.8.0` e `policy_update_from_height 40`.

Volta atrás: o binário anterior lê os dados até o primeiro bloco com uma
`UpdatePolicy`; depois dele, só com o backup.

## v2.9.0: recuperação v3 ligada no bloco 60, kits com as duas assinaturas (sem reset)

- A recuperação passa a assinar a mensagem inteira (v3) a partir do bloco
  60 da quantar-testnet-2 (`RECOVERY_V3_TESTNET2`). Até o 59 vale o resumo
  de 32 bytes; blocos antigos refazem igual. Com isso a recuperação deixa
  de ficar presa em uns 128 bits de resistência a colisão, abaixo da
  categoria 5 do ML-DSA-87 e do SLH-DSA-SHA2-256s.
- Kit de recuperação com as duas assinaturas: `proof` (a que a rede
  verifica quando o kit é feito, o resumo antigo até o bloco 60) e
  `proof_v3` (mensagem inteira). Carteira e watchtower usam a que o
  próximo bloco pede, então um kit feito agora atravessa a ativação sem
  ninguém mexer. Watchtower e carteira antigos continuam lendo `proof`.
- `qtrc-wallet guardian kit --from <kit> --recovery-key <chave> [--out <arquivo>]`
  refaz um kit antigo para o cofre como ele está, com as duas assinaturas.
  Confere as duas contra o cofre antes de gravar; sem `--out` troca o
  arquivo no lugar, sem nunca deixar a conta sem kit. Não precisa da
  chave da carteira e não manda nada para a rede.
- O watchtower avisa antes da ativação, uma vez por conta, se um kit não
  tem a assinatura v3 ou se ela não abre o cofre (`stops working at block 60`),
  e avisa de novo quando estiver resolvido. Depois da ativação, um kit
  antigo aparece como `KitStale`, inclusive junto de um ataque.
- `recover --kit` usa a assinatura certa sozinho; com um kit antigo depois
  da ativação, avisa para refazer o kit ou usar `--recovery-key`.

Deploy, seguidor primeiro (207.154.219.21), depois validador
(164.90.145.184). Os dois com a rede abaixo do bloco 55, para sobrar
tempo para os kits. Se a rede já estiver perto de 60, não faça o deploy:
a altura precisa subir no código antes.

1. `curl -s https://testnet.quantarnetwork.com/rpc/status`: `height` abaixo de 55.
2. Backup: `systemctl stop <serviços>` e
   `cp -a /var/lib/quantar /root/backup-quantar-$(date +%F)-v2.8`
3. Validador: `cd ~/hx-mempool && git pull`, `cd ~/quantar-testnet && git pull && cargo build --release`.
   O seguidor não compila: recebe o `qtrc-node` e o `qtrc-wallet` do validador por `scp`.
4. Seguidor: `install -m 755 qtrc-{node,wallet} /usr/local/bin/`.
   Validador: `install -m 755 target/release/qtrc-{node,faucet,wallet,watchtower} /usr/local/bin/`
5. Iniciar os serviços e conferir `systemctl is-active`.
6. `/status` mostra `version 0.9.0` e `recovery_v3_from_height 60`.
7. Kits do watchtower, antes do bloco 60: para cada conta em
   `/etc/quantar/watchtower.json`, rodar
   `qtrc-wallet guardian kit --from <kit> --recovery-key <chave>`
   onde a chave de recuperação estiver guardada, e copiar o kit novo
   para o caminho da config. O watchtower recarrega sozinho; o log
   (`journalctl -u quantar-watchtower`) mostra `kit ready for the v3 activation`.

Volta atrás: até o bloco 59 o binário anterior refaz a mesma chain (a
v0.8.0 tem a v3 em `u64::MAX`, mas nenhum bloco abaixo de 60 muda). Do
bloco 60 em diante, só com o backup.

## v2.10.0: quatro validadores votando a partir do bloco 100 (sem reset)

- Até o bloco 99, São Francisco (`TESTNET2_VALIDATOR`) continua fazendo
  os blocos sozinho, como sempre. Frankfurt, São Paulo e Tóquio já rodam
  como validadores, mas só copiam e conferem esses blocos pela porta p2p.
  A partir do 100, todo bloco precisa de prova de commit: precommits de
  mais de 2/3 dos quatro (`TESTNET2_BFT_FROM`, `TESTNET2_BFT_VALIDATORS`).
- `ChainState.pre_bft_validators`: quem fazia os blocos antes da troca.
  Sem isso os nós esperariam os blocos 1 a 99 em rodízio dos quatro e a
  rede recusaria a própria história.
- Na rede ao vivo, a lista e a altura vêm do código. O `--bft-config` só
  diz onde achar cada um (`p2p`) e precisa bater com o código; um
  validador sem ele não inicia. Em rede local, `--validator` é obrigatório
  quando a votação começa depois do bloco 1, e esse validador precisa
  estar entre os que votam.
- `/proof` traz a prova de commit; `qtrc-wallet proof` confere os votos
  do conjunto fixo no código. Cabeçalho de antes do bloco 100 só com
  `--before-switch`, porque depois da troca uma chave sozinha não basta.
- Chaves novas nos três servidores novos, geradas em cada um. As da
  devnet não são usadas: a devnet assina com o mesmo identificador de
  rede (`quantar-testnet-2`), então votos dela valeriam aqui.
- Mensagens de alturas futuras: só até 4 à frente ficam guardadas, e a
  busca de blocos que elas disparam acontece no máximo a cada 2 segundos.
- Revisão independente: nenhum achado crítico no consenso. Corrigidos o
  da carteira (alto) e os de configuração e fila (baixos).

Riscos que ficam, conhecidos:
- Se a chave de São Francisco for usada para fazer dois blocos diferentes
  na mesma altura antes do 100, a troca pode travar até uma intervenção
  manual. Não piora o que existe hoje: essa chave já controla a rede
  sozinha até lá.
- Votos e transações não carregam o hash da gênese, só o identificador
  da rede. Por isso nenhuma chave pode ser usada em duas redes com o
  mesmo identificador.
- Nós que não atualizarem: depois do 100 um nó antigo aceita blocos
  solo de São Francisco e recusa os votados. Os quatro precisam estar na
  v0.10.0 antes do 100; a altura atual era 21 quando ela foi fixada.
- A porta p2p aceita só os IPs das URLs da configuração, com limite por
  IP. Isso protege contra excesso de pedidos, não contra quem controla um
  desses IPs; as mensagens em si são todas conferidas pela assinatura.
- Ensaio local: `deploy/bft/rehearse-handover.sh`.
