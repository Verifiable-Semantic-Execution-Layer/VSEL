# Guia de Implementação — VSEL for Cairo/STARK Seed Grant

**Foco**: Como construir cada deliverable do grant, mapeando os artefatos VSEL existentes para Cairo/Starknet.

Você já sabe Cairo. Este guia é sobre o que construir, em que ordem, e como adaptar cada modelo VSEL para o contexto Starknet.

---

## 1. Estrutura do Projeto

```
vsel-cairo/
├── cairo/                          # Código Cairo
│   ├── Scarb.toml
│   ├── src/
│   │   ├── lib.cairo               # Entry point
│   │   ├── state.cairo             # State definition
│   │   ├── transitions.cairo       # External functions (transições)
│   │   ├── invariants.cairo        # Assertion helpers
│   │   └── events.cairo            # Events (observables)
│   └── tests/
│       └── test_state_machine.cairo
├── assurance/                      # Templates e metodologia VSEL
│   ├── semantic_gap_analysis.md    # Template adaptado para Cairo
│   ├── proof_obligations.md        # Schema de proof obligations
│   ├── trace_sufficiency.md        # Modelo de trace sufficiency
│   ├── constraint_coverage.md      # Matriz de constraint coverage
│   ├── witness_uniqueness.md       # Modelo de witness uniqueness
│   ├── verifier_binding.md         # Checklist de verifier binding
│   └── semantic_mapping.md         # Mapeamento VSEL → Cairo/Starknet
├── examples/                       # Exemplos aplicados ao contrato ref
│   ├── reference_gap_analysis.md
│   ├── reference_proof_obligations.md
│   ├── reference_constraint_coverage.md
│   └── reference_semantic_mapping.md
├── docs/
│   ├── overview.md                 # Visão geral do toolkit
│   ├── getting_started.md          # Como usar os templates
│   └── starknet_architecture.md    # Mapeamento de camadas
└── README.md
```

---

## 2. Milestone 1 — Adaptação e Pacote de Pesquisa (Semanas 1-3)

### 2.1 Mapeamento VSEL → Cairo/Starknet

O VSEL tem 6 camadas. Cada uma tem um equivalente direto no Starknet. O deliverable é um documento (`assurance/semantic_mapping.md`) que faz esse mapeamento explícito.

| Camada VSEL | Artefato VSEL | Equivalente Cairo/Starknet | O que muda na adaptação |
|---|---|---|---|
| **Formal Spec (FSL)** | `FORMAL_SPECIFICATION.md` | Não existe nativamente em Cairo. O toolkit adiciona essa camada via templates. | Criar template de spec formal para contratos Cairo |
| **SIR** | `vsel-sir/` | **Sierra** (Cairo → Sierra → CASM) | Sierra é o IR do Cairo. A diferença: Sierra é gerado automaticamente pelo compilador, SIR é definido manualmente. O gap semântico está entre o que o dev pretende e o que Sierra codifica. |
| **Execution** | `vsel-engine/` | **Sequencer** (executa transações Cairo) | No Starknet, execução é feita pelo sequencer. O dev não controla o runtime. O gap: o dev define funções Cairo, mas não controla como o sequencer as executa. |
| **State (S)** | `vsel-core/src/state.rs` | **Contract storage** (`#[storage]`) | Storage slots são felt252-addressed. Cada `StorageVariable` é um campo do state. |
| **Input (Σ)** | `vsel-core/src/input.rs` | **Calldata** (parâmetros de funções externas) + **tx context** (`get_caller_address()`, etc.) | Inputs incluem calldata + contexto de transação. Auth é via account abstraction, não via assinatura no input. |
| **Transition (T)** | `vsel-core/src/transition.rs` | **External functions** (`#[external(v0)]`) | Cada função externa é uma transição. `classify()` do VSEL → pattern matching no dispatcher Cairo. |
| **Observable (O)** | `vsel-core/src/observable.rs` | **Events** (`self.emit(...)`) | Events Cairo são os observables. Return values também. |
| **Invariants** | `vsel-invariants/` | **Assertions** (`assert!`) + **VSEL templates** | Cairo tem `assert!` mas não tem sistema de invariantes formal. O toolkit adiciona isso via documentação. |
| **Constraints** | `vsel-constraints/` | **STARK constraints** (geradas automaticamente por Cairo → Sierra → CASM → Trace → Proof) | No Starknet, constraints são automáticas. O dev não as escreve. O gap: ninguém verifica se as constraints automáticas cobrem todos os requisitos semânticos. |
| **Proof** | `vsel-proof/` | **SHARP/Stone/Stwo** (prover do Starknet) | Prover é infraestrutura Starknet. O dev não interage diretamente. |
| **Verification** | `vsel-proof/src/verifier.rs` | **L1 Verifier** (contrato Ethereum que verifica provas STARK) | Verificação é on-chain no L1. O dev não controla. |
| **Composition** | `vsel-composition/` | **Cross-contract calls** + **L2→L1 messages** + **composição de blocos** | Composição no Starknet é via chamadas entre contratos e mensagens L2→L1. |

### 2.2 Checklist de Semantic Assurance para Cairo

Adaptar a partir dos documentos VSEL existentes. O checklist deve ser prático — algo que um dev Cairo possa usar antes de um audit.

**Fonte**: `docs/SEMANTIC_GAP_ANALYSIS.md` + `docs/PROOF_OBLIGATIONS.md`

```markdown
# Cairo/STARK Semantic Assurance Checklist

## State Definition
- [ ] Todos os campos de storage estão documentados com tipo e semântica
- [ ] Campos derivados (e.g., totais, roots) são recomputáveis a partir do state canônico
- [ ] Não existe state oculto (variáveis que afetam comportamento mas não estão no storage)

## Transitions
- [ ] Cada função externa tem pré-condições documentadas
- [ ] Cada função externa tem pós-condições documentadas
- [ ] Campos não-mutados são explicitamente preservados (carry-over)
- [ ] Error paths não corrompem state

## Invariants
- [ ] Invariantes locais (por transição) estão documentados
- [ ] Invariantes globais (todo state válido) estão documentados
- [ ] Invariantes econômicos (conservação de recursos) estão documentados
- [ ] Invariantes temporais (ordering, no-rollback) estão documentados

## Observables
- [ ] Todos os events emitidos correspondem a mudanças semânticas reais
- [ ] Nenhuma mudança semântica ocorre sem event correspondente
- [ ] Return values são consistentes com o state pós-transição

## Proof Semantics
- [ ] O que a prova STARK atesta está documentado
- [ ] Gaps entre o que a prova atesta e o que a aplicação pretende estão identificados
- [ ] Witness uniqueness: não existe ambiguidade no que a prova representa
```

### 2.3 Publicação

- Criar página do projeto no site VSEL
- Publicar o mapeamento e o checklist como documentação pública
- Post de milestone update

---

## 3. Milestone 2 — Templates do Toolkit (Semanas 4-6)

### 3.1 Proof Obligation Schema para Cairo

**Fonte VSEL**: `docs/PROOF_OBLIGATIONS.md` (32 axiomas, 6 categorias)

No Starknet, o dev não escreve constraints manualmente. Mas ele precisa documentar o que a prova deve garantir. O schema adapta as categorias do VSEL:

```markdown
# Proof Obligation Schema — [Nome do Contrato]

## PO-1: State Validity Preservation
- Statement: Toda transição preserva a validade do state
- Cairo enforcement: assert! no início e fim de cada função externa
- STARK coverage: Automático (Cairo garante que assertions são parte do trace)
- Gap: Assertions cobrem todos os predicados de validade?

## PO-2: Resource Conservation
- Statement: Nenhuma transição cria ou destrói recursos
- Cairo enforcement: Verificação explícita de balanços antes/depois
- STARK coverage: Automático se a verificação está no código Cairo
- Gap: E se a verificação tem um bug? O STARK prova que o código executou, não que o código está correto.

## PO-3: Authorization Binding
- Statement: Cada transição é autorizada pelo caller correto
- Cairo enforcement: get_caller_address() + verificação de ownership
- STARK coverage: Automático (caller_address é parte do trace)
- Gap: Account abstraction permite lógica de auth customizada. A prova atesta que a auth function retornou true, não que a lógica de auth é correta.
```

**Ponto-chave para o template**: No Starknet, o gap semântico principal é entre "o código Cairo executou corretamente" (que a prova garante) e "o código Cairo implementa a semântica pretendida" (que a prova NÃO garante). O template deve focar nesse gap.

### 3.2 Semantic Gap Analysis Template

**Fonte VSEL**: `docs/SEMANTIC_GAP_ANALYSIS.md` (32 axiomas, 26 opaque functions, 5 camadas)

Adaptar para Cairo. Os gaps no Starknet são diferentes:

| Gap VSEL | Gap equivalente Cairo/Starknet |
|---|---|
| Formal spec ↔ SIR | Intenção do dev ↔ código Cairo |
| SIR ↔ Concrete execution | Cairo source ↔ Sierra ↔ CASM |
| Concrete ↔ Constraints | CASM execution ↔ STARK constraints (automático, mas opaco) |
| Constraints ↔ Proof | STARK constraints ↔ prova gerada (infraestrutura Starknet) |
| Proof ↔ Verification | Prova ↔ verificação L1 (infraestrutura Starknet) |

O template deve guiar o dev a identificar gaps em cada camada:

```markdown
# Semantic Gap Analysis — [Nome do Contrato]

## Gap 1: Intenção → Código Cairo
- Intenção documentada: [o que o contrato deveria fazer]
- Código Cairo: [o que o código realmente faz]
- Divergências identificadas: [lista]
- Severidade: [crítica/alta/média/baixa]

## Gap 2: Cairo → Sierra (compilação)
- Otimizações do compilador que podem afetar semântica: [lista]
- Comportamento de overflow/underflow: [felt252 wraps, u256 panics]
- Reentrancy: [Cairo não tem reentrancy guard nativo — é um gap?]

## Gap 3: Execution → Proof Statement
- O que a prova STARK atesta: [execução do CASM satisfez constraints]
- O que a aplicação precisa: [semântica de negócio preservada]
- Gap: [a prova não verifica invariantes de negócio que não estão no código]
```

### 3.3 Trace Sufficiency Template

**Fonte VSEL**: `docs/TRACE_SUFFICIENCY.md` (6 condições SUFF, 3 teoremas THM-SUFF)

No Starknet, o trace é gerado automaticamente pelo sequencer. O dev não controla o formato. Mas ele precisa verificar que o trace captura tudo que é semanticamente relevante.

Adaptar as condições SUFF:

| Condição VSEL | Equivalente Cairo/Starknet |
|---|---|
| SUFF-1: State Determinism | Cairo é determinístico por design (Sierra garante terminação) |
| SUFF-2: Input Completeness | Calldata é completo no trace. Mas: `get_block_timestamp()` e outros syscalls são inputs implícitos — estão no trace? |
| SUFF-3: Observable Completeness | Events são parte do trace. Return values também. |
| SUFF-4: Ordering Completeness | Transações dentro de um bloco têm ordem definida pelo sequencer. |
| SUFF-5: Environment Completeness | Block context (timestamp, block_number, sequencer_address) — está no trace? |
| SUFF-6: No Hidden Transitions | Internal function calls são parte do trace. Mas: delegate_call e library_call podem ter efeitos ocultos. |

### 3.4 Witness Uniqueness Template

**Fonte VSEL**: `docs/WITNESS_UNIQUENESS_AND_NON_MALLEABILITY.md` (6 classes MAL, 4 condições U)

No Starknet, o witness é gerado pelo prover (SHARP/Stone/Stwo). O dev não o controla. Mas ele precisa entender quando o witness pode ser ambíguo.

Adaptar as classes de malleability:

| Classe VSEL | Equivalente Cairo/Starknet |
|---|---|
| MAL-1: State Substitution | Dois states diferentes com mesmo state root (collision) |
| MAL-2: Input Substitution | Dois calldata diferentes que produzem a mesma transição |
| MAL-3: Observable Manipulation | Events emitidos não correspondem ao state change real |
| MAL-4: Authorization Rebinding | Assinatura de uma transação usada para autorizar outra (account abstraction) |
| MAL-5: Temporal Reordering | Reordenação de transações dentro de um bloco pelo sequencer |
| MAL-6: Cross-Proof Sharing | Prova de um bloco usada em contexto de outro bloco |

### 3.5 Constraint Coverage Matrix Template

**Fonte VSEL**: `docs/CONSTRAINT_COVERAGE_MATRIX.md`

No Starknet, constraints são automáticas. Mas o template ajuda o dev a verificar que cada requisito semântico tem enforcement no código Cairo:

```markdown
| Requisito Semântico | Função Cairo | Enforcement | Tipo | Coberto por STARK? |
|---|---|---|---|---|
| Saldo nunca negativo | transfer() | assert!(balance >= amount) | assert | Sim (assertion é parte do trace) |
| Só owner pode pausar | pause() | assert!(caller == owner) | assert | Sim |
| Total supply constante | transfer() | Nenhum (implícito) | NENHUM | ⚠️ Gap — não há assert explícito |
```

### 3.6 Verifier Binding Checklist

**Fonte VSEL**: Combinação de `PROOF_OBLIGATIONS.md` (PROOF-1 a PROOF-4) + `VERIFICATION_LAYER.md`

```markdown
# Verifier Binding Checklist — [Nome do Contrato]

## 1. A prova atesta execução completa?
- [ ] Todas as transições do bloco estão no trace
- [ ] Nenhuma transição foi omitida ou resumida

## 2. Public inputs são suficientes?
- [ ] State root pré e pós estão nos public inputs
- [ ] Block hash está nos public inputs
- [ ] Todos os events estão commitados

## 3. Domain separation?
- [ ] Provas de um bloco não são reutilizáveis em outro
- [ ] Chain ID está nos public inputs

## 4. Verifier L1 valida tudo?
- [ ] State root é atualizado no L1 contract
- [ ] Proof é verificada antes de aceitar state update
```

---

## 4. Milestone 3 — Contrato de Referência Cairo (Semanas 7-9)

### 4.1 O que construir

Um contrato Cairo minimal que demonstra a metodologia. Não precisa ser complexo — precisa ser claro.

**State machine de referência**: Um vault simples com deposit, withdraw, e transfer.

```cairo
#[starknet::contract]
mod VselVault {
    use starknet::ContractAddress;
    use starknet::get_caller_address;

    #[storage]
    struct Storage {
        balances: LegacyMap<ContractAddress, u256>,
        total_supply: u256,
        owner: ContractAddress,
        paused: bool,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        Deposit: Deposit,
        Withdraw: Withdraw,
        Transfer: Transfer,
    }

    // ... transitions com invariantes documentados
}
```

### 4.2 Aplicar cada template ao contrato

Para cada template do Milestone 2, criar um exemplo preenchido usando o contrato de referência:

1. **Semantic mapping** — Mapear cada campo de storage para o modelo formal
2. **Proof obligations** — Listar o que cada prova deve garantir para o vault
3. **Semantic gap analysis** — Identificar gaps entre intenção e implementação
4. **Trace sufficiency** — Verificar que o trace captura tudo
5. **Constraint coverage** — Mapear cada invariante para seu enforcement no código
6. **Witness uniqueness** — Analisar se o witness é ambíguo
7. **Verifier binding** — Verificar que a prova L1 cobre tudo

### 4.3 Deploy no Sepolia

```bash
# Build
scarb build

# Declare
sncast declare --contract-name VselVault

# Deploy
sncast deploy --class-hash <hash> --constructor-calldata <owner_address>
```

Documentar o endereço do deploy e linkar na documentação.

### 4.4 Tutorial

Escrever um artigo tutorial mostrando como usar os templates no contrato de referência. Formato: "Aqui está um contrato Cairo. Aqui está como aplicar a metodologia VSEL para identificar gaps semânticos antes do audit."

---

## 5. Ordem de Execução Recomendada

| Semana | Foco | Deliverable |
|---|---|---|
| 1 | Mapeamento VSEL → Cairo/Starknet | `assurance/semantic_mapping.md` |
| 2 | Checklist + estrutura do projeto | Checklist + repo structure |
| 3 | Publicação M1 | Website update + milestone post |
| 4 | Templates: proof obligations + semantic gap | `assurance/proof_obligations.md` + `assurance/semantic_gap_analysis.md` |
| 5 | Templates: trace + witness + constraint + verifier | Restante dos templates |
| 6 | Publicação M2 | Technical write-up + milestone post |
| 7 | Contrato Cairo de referência | `cairo/src/*.cairo` + testes |
| 8 | Exemplos aplicados + deploy Sepolia | `examples/*.md` + deploy |
| 9 | Tutorial + publicação M3 | Tutorial article + final report |

---

## 6. O que NÃO fazer

- **Não portar o prover VSEL para Cairo.** O grant é sobre metodologia e templates, não sobre substituir SHARP/Stwo.
- **Não construir um analisador automático.** Isso é pós-grant. O Seed Grant entrega templates manuais e documentação.
- **Não fingir que o contrato de referência é production-ready.** É educacional. Label claro.
- **Não complicar o contrato de referência.** Quanto mais simples, melhor para demonstrar a metodologia. Um vault com 3 funções é suficiente.
- **Não ignorar os gaps reais do Starknet.** O valor do toolkit é ser honesto sobre onde as provas STARK não cobrem a semântica da aplicação. Se você suavizar os gaps, o toolkit perde valor.

---

## 7. Preparação para Follow-up Questions

Se a Starknet Foundation fizer perguntas durante o screening:

**"Como isso se diferencia de Starknet Foundry / testing tools?"**
> Foundry testa se o código executa como implementado. VSEL verifica se o que foi implementado preserva a semântica pretendida. São complementares. Foundry: "o código funciona?" VSEL: "o código significa o que deveria significar?"

**"Vocês vão modificar infraestrutura Starknet?"**
> Não. O toolkit opera ao lado do desenvolvimento Cairo. Produz documentação e templates. Não toca no prover, verifier, ou sequencer.

**"Qual é o gap principal que o VSEL identifica no Starknet?"**
> No Starknet, a prova STARK garante que o código Cairo executou corretamente. Mas não garante que o código Cairo implementa a semântica pretendida da aplicação. Um contrato pode ter um bug lógico, executar o bug corretamente, e produzir uma prova válida para uma execução incorreta. O VSEL ajuda a identificar esses gaps antes que virem exploits.

**"Por que não automatizar a análise?"**
> Automação é o objetivo de longo prazo. O Seed Grant entrega a base: metodologia validada, templates testados, e um exemplo de referência. Automatizar sem ter a metodologia correta primeiro produz ferramentas que dão falsa confiança.
