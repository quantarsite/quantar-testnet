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
