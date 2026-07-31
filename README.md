# Análise Quantitativa do Peso Unitário de Custom Entities no CrowdStrike AIDR

[![Cybersecurity](https://img.shields.io/badge/Domain-Cybersecurity%20%26%20DLP-blue.svg)](#)
[![AIDR](https://img.shields.io/badge/Platform-CrowdStrike%20AIDR-red.svg)](#)
[![Status](https://img.shields.io/badge/Status-Validated-success.svg)](#)

---

## Abstract (Resumo)

O **CrowdStrike AIDR (AI Detection & Response)** é uma solução voltada para a segurança no uso de IA generativa no ambiente corporativo. A ferramenta possibilita a criação de Custom Entities, nas quais a lógica de detecção depende da pontuação agregada gerada pela combinação de expressões regulares (*Regex Match*) e contextos associados (*Regular Context* e *Negative Context*). 

Este estudo apresenta uma análise quantitativa e empírica para derivar a função matemática e os pesos unitários (*unit weights*) utilizados pelo AIDR no cálculo do Score das Custom Entities. A partir de cenários de teste estruturados, demonstrou-se que cada termo de Regular Context contribui com **$+0{,}35$** e cada termo de Negative Context subtrai **$-0{,}20$** do valor base do *Regex Match*. Os resultados permitem transicionar a engenharia de detecção de um modelo empírico (tentativa e erro) para uma abordagem determinística.

---

## Declaração do Problema e Motivação

### Problema
No CrowdStrike AIDR, múltiplos elementos contextuais interagem com correspondências de *Regex*. A ausência de previsibilidade sobre o peso exato de cada termo gera dois problemas críticos na operação:
1. **Falsos Positivos (Over-blocking):** Bloqueio de ações legítimas devido ao peso excessivo acumulado por termos contextuais.
2. **Falsos Negativos (Under-blocking):** Falha em interceptar *prompts* maliciosos ou vazamentos acidentais quando a presença de termos atenuantes (*Negative Context*) reduz indevidamente o Score final abaixo do limiar de bloqueio.

### Motivação
Determinar o peso unitário ($W$) atribuído a cada variável possibilita calibrar as regras com precisão, alinhando os limiares (*thresholds*) diretamente ao nível de risco tolerável pela organização.

---

## Testes e Observações Empíricas

A metodologia experimental consistiu em isolar a pontuação base da expressão regular (*Regex Match Score*) e submeter *prompts* contendo variações controladas de termos de Regular Context e Negative Context, ajustando incrementalmente o *Threshold* de bloqueio na política da plataforma.

### Nomenclatura e Variáveis
* $R$: Pontuação base do *Regex Match* ($0{,}0 \le R \le 1{,}0$)
* $n$: Quantidade de termos de Regular Context identificados no *prompt*
* $m$: Quantidade de termos de Negative Context identificados no *prompt*
* $W_{\text{reg}}$: Peso unitário de um termo de Regular Context
* $W_{\text{neg}}$: Peso unitário de um termo de Negative Context
* $T$: Limiar de bloqueio configurado na regra da política (*Threshold*)

---

### Cenários de Teste Executados

#### Teste 1: Impacto de Contexto Misto ($2 \times \text{Regular Context} + 1 \times \text{Negative Context}$ com $R = 0{,}5$)
* **Cálculo Observado:** $0{,}50 + (2 \times 0{,}35) - (1 \times 0{,}20) = 0{,}50 + 0{,}70 - 0{,}20 = 1{,}00$
* **Configuração do Teste:** *Threshold* $T = 1{,}0$
* **Resultado Obtido:** **BLOCKED**
* **Conclusão:** O Score atingiu exatamente o limite superior da escala ($1{,}0$), confirmando o impacto acumulado dos termos.

#### Teste 2: Atenuação por Segundo Contexto Negativo ($2 \times \text{Regular Context} + 2 \times \text{Negative Context}$ com $R = 0{,}5$)
* **Cálculo Observado:** $0{,}50 + (2 \times 0{,}35) - (2 \times 0{,}20) = 0{,}50 + 0{,}70 - 0{,}40 = 0{,}80$
* **Configuração do Teste:**
  * Com $T = 0{,}9 \rightarrow$ **ALLOWED** ($0{,}80 < 0{,}90$)
  * Com $T = 0{,}8 \rightarrow$ **BLOCKED** ($0{,}80 \ge 0{,}80$)
* **Conclusão:** A adição do segundo termo de Negative Context reduz o Score acumulado de $1{,}00$ para $0{,}80$, confirmando a penalidade exata de $-0{,}20$ por termo.

#### Teste 3: Limiar Baixo com Contexto Misto ($1 \times \text{Regular Context} + 1 \times \text{Negative Context}$ com $R = 0{,}1$)
* **Cálculo Observado:** $0{,}10 + (1 \times 0{,}35) - (1 \times 0{,}20) = 0{,}10 + 0{,}35 - 0{,}20 = 0{,}25$
* **Configuração do Teste:** *Threshold* $T = 0{,}2$
* **Resultado Obtido:** **BLOCKED**
* **Conclusão:** Como o Score final calculado foi $0{,}25$, a condição $0{,}25 \ge 0{,}20$ disparou a ação de bloqueio.

#### Teste 4: Efeito de Contexto Líquido Negativo ($1 \times \text{Regular Context} + 2 \times \text{Negative Context}$)
* **Cálculo Observado:** $R + (1 \times 0{,}35) - (2 \times 0{,}20) = R - 0{,}05$
* **Resultado Obtido:** O bloqueio ocorreu apenas quando o *Threshold* foi ajustado para valores estritamente inferiores a $R - 0{,}05$.
* **Conclusão:** Comprovou-se que um saldo de contexto líquido negativo ($n \cdot W_{\text{reg}} - m \cdot W_{\text{neg}} < 0$) reduz ativamente a pontuação base gerada pelo *Regex Match*.

---

## Modelo Matemático e Fórmula

A partir da consolidação dos testes empíricos, formaliza-se a equação do motor de avaliação do Score para Custom Entities no CrowdStrike AIDR:

$$\text{Score} = R + (n \cdot W_{\text{reg}}) - (m \cdot W_{\text{neg}})$$

Substituindo os valores das constantes identificadas:

$$\text{Score} = R + (n \cdot 0{,}35) - (m \cdot 0{,}20)$$

A condição lógica da ação de política é dada por:

$$\text{Ação} = 
\begin{cases} 
\text{BLOCK}, & \text{se } \text{Score} \ge T \\
\text{ALLOW}, & \text{se } \text{Score} < T 
\end{cases}$$

---

### Prova de Validação (Predição Teórica vs. Execução Prática)

Para testar a capacidade preditiva do modelo formalizado, um teste de validação foi estruturado da seguinte forma:

1. **Parâmetros de Entrada:**
   * Pontuação Base do *Regex Match* ($R$): $0{,}10$
   * Termos de Regular Context ($n$): $3 \Rightarrow 3 \times 0{,}35 = +1{,}05$
   * Termos de Negative Context ($m$): $2 \Rightarrow 2 \times (-0{,}20) = -0{,}40$
2. **Cálculo do Score:**
   $$\text{Score} = 0{,}10 + 1{,}05 - 0{,}40 = \mathbf{0{,}75}$$

3. **Resultados de Execução no AIDR:**
   * **Cenário A (*Threshold* $T = 0{,}8$):**
     * *Resultado Previsto:* **ALLOW** ($0{,}75 < 0{,}80$)
     * *Resultado no Sistema:* **ALLOWED** ✅
   * **Cenário B (*Threshold* $T = 0{,}7$):**
     * *Resultado Previsto:* **BLOCK** ($0{,}75 \ge 0{,}70$)
     * *Resultado no Sistema:* **BLOCKED** ✅

A validação confirmou a exata correspondência entre o modelo matemático derivado e o comportamento da ferramenta em produção.

---

*Relatório de pesquisa elaborado para calibração e sintonia de regras no CrowdStrike AIDR. A documentação foi submetida à CrowdStrike, que realizou os testes internos e confirmou os resultados.*
