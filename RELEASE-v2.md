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

1. Backup do que existe hoje, por segurança:
   `docker compose down` e copie a pasta de dados da v1 para outro lugar

2. Atualize o código nas duas pastas irmãs:
   `git -C hx-mempool pull` e `git -C quantar-testnet pull`

3. Compile:
   `cd quantar-testnet && cargo build --release`

4. Gere as duas chaves, uma vez só, e guarde backup fora do servidor:
   `./target/release/qtrc-node keygen --out /etc/quantar/node.key`
   `./target/release/qtrc-node keygen --out /etc/quantar/faucet.key`
   Anote o `Address` completo (64 caracteres hex) do faucet

5. Suba o node com o endereço do faucet no gênesis, numa pasta de dados nova
   e fora do container, para sobreviver a rebuild:
   `QTR_FAUCET_ADDRESS=<endereco do faucet> ./target/release/qtrc-node start --key-file /etc/quantar/node.key --data-dir /var/lib/quantar`
   Nos próximos reinícios use a mesma pasta. O gênesis já fica salvo nela

6. No nginx do faucet, garanta `proxy_set_header X-Real-IP $remote_addr;`,
   senão todo mundo aparece com o IP do próprio servidor e o limite por IP
   trava o faucet para todos depois do primeiro drip

7. Suba o faucet com a chave dele:
   `./target/release/qtrc-faucet --key-file /etc/quantar/faucet.key --node-rpc http://127.0.0.1:8545`

8. Confira:
   `curl localhost:8545/status` tem que mostrar `"chain_id":"quantar-testnet-2"` e `"version":"0.2.0"`
   `curl localhost:8545/account/<endereco do faucet>` tem que mostrar 10.000.000 QTR

9. Se o faucet público em faucet.quantarnetwork.com é o serviço separado
   (quantar-faucet-service, com Redis), ele também precisa passar a assinar
   com a chave do faucet v2 antes de voltar ao ar

## Testes que provam a v2

- `crates/qtrc-consensus/tests/hydrax_v2.rs`: transação assinada pelo núcleo
  passa pelo mempool, entra num bloco e muda o saldo; assinatura no layout da
  v1 é rejeitada; o prefixo de domínio é idêntico nos dois repos
- `hx-mempool/tests/hydrax_v2.rs`: assinatura SLH-DSA FIPS 205 real verifica
  pela rota de produção
- Testado de ponta a ponta com os binários: keygen, node, faucet, dois drips
  seguidos com nonces 0 e 1, saldos conferidos
