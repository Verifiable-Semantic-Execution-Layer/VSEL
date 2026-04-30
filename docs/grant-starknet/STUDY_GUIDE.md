# Guia de Estudo — Preparação para o Starknet Seed Grant

**Objetivo**: Te preparar para possíveis follow-up questions da Starknet Foundation e para executar o grant com confiança.

O processo deles é: Submission → Pre-screening (5 dias úteis) → Screening → Follow-up questions (opcional) → Decisão. O ciclo completo leva ~4 semanas. Você precisa estar pronto para responder perguntas técnicas sobre Cairo, Starknet, e como o VSEL se encaixa.

---

## 1. Cairo — O Essencial

Cairo é a linguagem de programação do Starknet. Não é Solidity. Não é Rust. É uma linguagem projetada para computação provável.

### O que estudar primeiro

| Tópico | Recurso | Prioridade |
|---|---|---|
| Cairo Book (oficial) | https://book.cairo-lang.org/ | 🔴 Alta |
| Starklings (exercícios interativos) | https://github.com/shramee/starklings-cairo1 | 🔴 Alta |
| Scarb (build tool do Cairo) | https://docs.swmansion.com/scarb/ | 🟡 Média |
| Starknet Foundry (testing/deploy) | https://foundry-rs.github.io/starknet-foundry/ | 🟡 Média |
| Cairo by Example | https://cairo-by-example.com/ | 🟢 Complementar |

### Conceitos-chave do Cairo que você precisa dominar

1. **Felt252** — O tipo primitivo do Cairo. É um field element no campo primo p = 2^251 + 17·2^192 + 1. Diferente do Goldilocks (2^64 − 2^32 + 1) que o VSEL usa. Você vai precisar mapear conceitos.

2. **Sierra** — Safe Intermediate Representation. Cairo compila para Sierra, que depois compila para CASM (Cairo Assembly). Sierra garante que toda execução termina — não existe infinite loop. Isso é relevante para o VSEL porque Sierra é análogo ao SIR (Semantic Intermediate Representation) do VSEL.

3. **Storage** — Contratos Cairo têm storage on-chain. Cada variável de storage é um felt252 endereçado por hash. Isso é o "state" no modelo VSEL.

4. **Events** — Cairo emite events que são os "observables" no modelo VSEL.

5. **Traits e Impls** — Cairo usa um sistema de traits similar ao Rust. Você já conhece isso.

6. **Snapshots (@)** — Cairo tem ownership como Rust, mas com snapshots (@T) em vez de references. Importante para entender como state é lido sem mover ownership.

### Exercício prático recomendado

Escreva um contrato Cairo simples com:
- Um storage com `balance: u256` e `owner: ContractAddress`
- Uma função `transfer(to, amount)` que verifica saldo e transfere
- Um event `Transfer(from, to, amount)`
- Um invariante: `total_supply` nunca muda

Isso é exatamente o tipo de "minimal reference state machine" que o Milestone 3 pede.

---

## 2. Starknet — Arquitetura

### O que estudar

| Tópico | Recurso | Prioridade |
|---|---|---|
| Starknet docs (oficial) | https://docs.starknet.io/ | 🔴 Alta |
| Starknet architecture | https://docs.starknet.io/architecture-and-concepts/ | 🔴 Alta |
| Account abstraction | https://docs.starknet.io/architecture-and-concepts/accounts/ | 🟡 Média |
| Starknet Sepolia testnet | https://docs.starknet.io/tools/devtools/ | 🟡 Média |

### Conceitos-chave

1. **Sequencer** — Recebe transações, executa, e produz blocos. Análogo ao "execution engine" do VSEL.

2. **Prover (SHARP/Stone/Stwo)** — Gera provas STARK das execuções. O Starknet está migrando para Stwo (novo prover). Isso é o "Proof Layer" do VSEL.

3. **Verifier (on-chain L1)** — Contrato Ethereum que verifica as provas STARK. Isso é o "Verification Layer" do VSEL.

4. **State commitment** — Starknet usa uma Patricia-Merkle trie para o state. O state root é commitado no L1. Análogo ao `state_root` e `chain_hash` do VSEL.

5. **Transaction lifecycle**: Transação → Sequencer → Execução → Bloco → Prova → Verificação L1. Cada etapa tem um mapeamento direto para as camadas do VSEL.

---

## 3. Mapeamento VSEL → Cairo/Starknet

Este é o coração do que você vai entregar no Milestone 1. Estude esta tabela:

| Camada VSEL | Equivalente Cairo/Starknet | Notas |
|---|---|---|
| Formal Specification Layer | Cairo contract interface + NatSpec-style docs | Cairo não tem spec formal nativa; VSEL adiciona essa camada |
| SIR (Semantic IR) | Sierra | Sierra é o IR seguro do Cairo; paralelo natural ao SIR |
| Execution Layer | Sequencer + Cairo VM | Execução determinística de contratos |
| State (S) | Contract storage | felt252-addressed storage slots |
| Input (Σ) | Transaction calldata | Parâmetros de função + contexto de transação |
| Transition (T) | External functions | Cada `fn` externa é uma transição de estado |
| Observable (O) | Events | `emit` events são os observáveis |
| Invariants | Assertions + VSEL methodology | Cairo tem `assert!` mas não tem sistema de invariantes formal |
| Constraint System | STARK constraints (automático) | Cairo → Sierra → CASM → execution trace → STARK proof |
| Proof Layer | SHARP/Stone/Stwo prover | Gera provas STARK automaticamente |
| Verification Layer | L1 verifier contract | Verifica provas on-chain no Ethereum |
| Composition | L2 → L1 state updates, cross-contract calls | Composição de provas entre blocos e contratos |

### O gap que o VSEL preenche

No Starknet, a cadeia Cairo → Sierra → CASM → Trace → Proof → Verify é automática. O desenvolvedor não toca nas constraints. Isso é ótimo para usabilidade, mas cria um gap: **ninguém documenta formalmente o que a prova realmente atesta em termos de semântica da aplicação**.

O VSEL toolkit preenche esse gap com:
- Documentação formal do que cada prova deve garantir (proof obligations)
- Análise de onde a semântica pode divergir (semantic gap analysis)
- Verificação de que o trace captura toda a execução relevante (trace sufficiency)
- Confirmação de que as constraints cobrem todos os requisitos (constraint coverage)

---

## 4. Perguntas Prováveis do Grant Review

Prepare respostas para estas perguntas. A Starknet Foundation pode fazer follow-up questions.

### Técnicas

**Q: Como o VSEL se diferencia de ferramentas de testing como Starknet Foundry?**
> Starknet Foundry testa se o código funciona como implementado. VSEL verifica se o que foi implementado preserva a semântica pretendida. São camadas complementares: Foundry testa código, VSEL assegura significado.

**Q: Cairo já compila para constraints automaticamente. Por que precisamos de constraint coverage?**
> A compilação automática garante que a execução satisfaz as constraints geradas. Mas não garante que as constraints geradas capturam todos os requisitos semânticos da aplicação. Um contrato pode compilar e provar corretamente, mas ter invariantes econômicos ou de estado que não estão refletidos nas constraints.

**Q: Vocês vão modificar o prover ou o verifier do Starknet?**
> Não. O VSEL toolkit é uma camada de assurance que opera ao lado do desenvolvimento Cairo. Não modifica infraestrutura Starknet. Produz documentação, templates, e metodologia que ajudam desenvolvedores a raciocinar sobre correção semântica.

**Q: Qual é a diferença entre o VSEL core (Rust/Plonky3) e o toolkit Cairo?**
> O VSEL core é um protocolo de verificação semântica completo com provas STARK reais. O toolkit Cairo é uma adaptação da metodologia e dos modelos formais do VSEL para o ecossistema Cairo/Starknet. O toolkit não porta o prover — ele porta a metodologia de assurance.

### Estratégicas

**Q: Como vocês vão medir sucesso?**
> Completude dos deliverables, feedback de desenvolvedores Cairo, adoção dos templates por equipes preparando auditorias, e engajamento da comunidade (GitHub stars, issues, PRs, feedback direto).

**Q: Qual é o plano pós-grant?**
> O toolkit open-source continua disponível. Monetização futura via serviços de consultoria em semantic assurance, auditorias de proof obligations, e reviews de constraint coverage para projetos Starknet. O core permanece open-source.

**Q: Por que Starknet e não outra chain?**
> Starknet coloca computação provável no centro do modelo de desenvolvimento. Cairo é a única linguagem mainstream projetada para provas STARK. Isso torna Starknet o ecossistema natural para semantic assurance — a pergunta "o que a prova prova?" é mais relevante aqui do que em qualquer outra chain.

---

## 5. Plano de Estudo — Semana a Semana

### Semana 1: Cairo Basics
- [ ] Ler Cairo Book capítulos 1-6 (tipos, ownership, structs, enums, pattern matching)
- [ ] Completar Starklings exercícios 1-15
- [ ] Escrever um contrato "Hello Starknet" com storage e events

### Semana 2: Cairo Avançado + Starknet
- [ ] Ler Cairo Book capítulos 7-12 (traits, generics, testing, smart contracts)
- [ ] Ler Starknet docs: architecture, accounts, transactions
- [ ] Escrever o contrato de referência (balance + transfer + invariant)
- [ ] Testar com Starknet Foundry localmente

### Semana 3: Deploy + Mapeamento VSEL
- [ ] Configurar Scarb project structure
- [ ] Deploy do contrato de referência no Starknet Sepolia
- [ ] Escrever o primeiro draft do mapeamento VSEL → Cairo/Starknet
- [ ] Escrever o primeiro draft do semantic assurance checklist

### Semana 4: Preparação para Follow-up
- [ ] Preparar respostas para as perguntas prováveis (seção 4 acima)
- [ ] Revisar o pitch document
- [ ] Ter o contrato de referência funcionando no Sepolia
- [ ] Publicar um post técnico curto sobre semantic assurance para Cairo

---

## 6. Ferramentas para Instalar

```bash
# Cairo e Scarb
curl -L https://raw.githubusercontent.com/software-mansion/asdf-scarb/main/install.sh | sh
asdf plugin add scarb
asdf install scarb latest
asdf global scarb latest

# Starknet Foundry
curl -L https://raw.githubusercontent.com/foundry-rs/starknet-foundry/master/scripts/install.sh | sh
snfoundryup

# Verificar instalação
scarb --version
snforge --version
sncast --version
```

---

## 7. Recursos Adicionais

| Recurso | URL | Para quê |
|---|---|---|
| Starknet ecosystem | https://www.starknet.io/ecosystem/ | Ver o que já existe |
| Awesome Starknet | https://github.com/keep-starknet-strange/awesome-starknet | Curadoria de projetos |
| Starknet Discord | https://discord.gg/starknet | Comunidade, feedback |
| Cairo Playground | https://www.cairo-lang.org/playground/ | Testar código rápido |
| Voyager (block explorer) | https://voyager.online/ | Inspecionar contratos Sepolia |
| Starkscan | https://starkscan.co/ | Alternativa ao Voyager |

---

## 8. Resumo

O grant já foi submetido. O review leva ~4 semanas. Nesse tempo:

1. **Aprenda Cairo** — Cairo Book + Starklings. Você já sabe Rust, então a curva é suave.
2. **Entenda Starknet** — Arquitetura, sequencer, prover, verifier. Mapeie para as camadas VSEL.
3. **Construa o contrato de referência** — Um contrato Cairo simples com state, transitions, observables, e invariants. Isso é o Milestone 3, mas começar agora te dá confiança.
4. **Prepare respostas** — Se vierem follow-up questions, você precisa responder com clareza técnica sobre Cairo e sobre como o VSEL se aplica.

Boa sorte com o grant. O VSEL v1.0 é real, documentado, auditado, e honesto. Isso é mais do que a maioria dos projetos que aplicam para grants pode dizer.
