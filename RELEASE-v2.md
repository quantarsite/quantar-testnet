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
- Versão 0.2.0 em todos os crates

## O que ainda não mudou (não fingir que mudou)

- O estado da chain ainda vive só em memória. O `BlockStore` abre, mas não é
  usado, então reiniciar o node zera a chain. Próximo item da lista
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

5. Suba o node com o endereço do faucet no gênesis:
   `QTR_FAUCET_ADDRESS=<endereco do faucet> ./target/release/qtrc-node start --key-file /etc/quantar/node.key`

6. Suba o faucet com a chave dele:
   `./target/release/qtrc-faucet --key-file /etc/quantar/faucet.key --node-rpc http://127.0.0.1:8545`

7. Confira:
   `curl localhost:8545/status` tem que mostrar `"chain_id":"quantar-testnet-2"` e `"version":"0.2.0"`
   `curl localhost:8545/account/<endereco do faucet>` tem que mostrar 10.000.000 QTR

8. Se o faucet público em faucet.quantarnetwork.com é o serviço separado
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
