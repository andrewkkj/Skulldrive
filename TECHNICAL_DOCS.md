# Documentação Técnica - Skulldrive

## Arquitetura do Sistema

### Visão Geral
A **Skulldrive** é uma estrutura de testes de penetração de alto desempenho, projetada para operações ofensivas avançadas de segurança. Ela oferece:

- **Núcleo em C**: Otimização de desempenho em baixo nível
- **Interface em Python**: Orquestração de alto nível e análises
- **Módulos Especializados**: Vetores de ataque direcionados e técnicas de evasão

### Estrutura de Arquivos
```
Skulldrive/
├── main.py                  # Interface principal CLI
├── python/                  # Módulos Python
│   ├── engine.py            # Engine principal de ataques
│   ├── analyzer.py          # Módulo de análise de alvos
│   ├── payload_mutator.py   # Motor de mutação de payloads
│   ├── stealth_utils.py     # Utilitários de furtividade
│   └── ioc_generator.py     # Gerador de IoCs
├── core/                    # Núcleo em C para performance
│   ├── engine_core.c        # Lógica central dos ataques
│   ├── packet_utils.c       # Utilitários de pacotes
│   └── stealth_core.c       # Funções furtivas em baixo nível
├── config/                  # Arquivos de configuração
├── payloads/                # Payloads customizados e mutações
├── ioc/                     # Indicadores de Comprometimento
└── examples/                # Exemplos de uso e templates
```

## Módulos Principais

### 1. Engine Principal (`python/engine.py`)
**Responsabilidades:**
- Orquestração dos ataques
- Gerenciamento de threads
- Integração com o núcleo em C
- Controle do fluxo de execução

**Classes-Chave:**
- `AttackEngine`: Orquestrador principal
- `WorkerThread`: Threads paralelas
- `AttackController`: Gerenciador do ciclo de vida do ataque

### 2. Analisador de Alvo (`python/analyzer.py`)
**Capacidades:**
- Verificação de conectividade
- Escaneamento de portas e serviços
- Fingerprinting de protocolos
- Detecção de vulnerabilidades
- Geração de relatórios

**Métodos principais:**
```python
def analyze(self) -> dict
def _analyze_connectivity(self)
def _analyze_ports(self)
def _analyze_protocols(self)
def _analyze_vulnerabilities(self)
```

### 3. Mutador de Payloads (`python/payload_mutator.py`)
**Técnicas de Mutação:**
- Injeção de caracteres aleatórios
- Codificação Base64
- Criptografia XOR
- Compressão simulada
- Ofuscação & polimorfismo

**Algoritmos de Mutação:**
```python
def mutate_syn_payload(self) -> bytes
def mutate_http_payload(self) -> bytes
def mutate_headers(self, headers: dict) -> dict
```

### 4. Utilitários de Furtividade (`python/stealth_utils.py`)
**Técnicas de Furtividade:**
- Atrasos aleatórios
- IP spoofing
- Rotação de User-Agent
- Simulação de headers legítimos
- Jitter de tempo

### 5. Gerador de IoC (`python/ioc_generator.py`)
**Formatos Suportados:**
- JSON
- STIX
- Sigma
- YARA

**Tipos de IoC:**
- IPs e domínios maliciosos
- URLs de C&C
- Hashes de malware
- E-mails de phishing
- Artefatos do Registro do Windows

## Núcleo em C Nativo (`core/`)

### 1. Núcleo da Engine (`engine_core.c`)
**Responsabilidades:**
- Multithreading
- Execução da lógica de ataque
- Manipulação de sockets raw
- Monitoramento de performance

**Funções-Chave:**
```c
int engine_init(const char *target_ip, int target_port, ...)
int start_slow_attack()
int start_saturation_attack()
void *slow_attack_worker(void *arg)
void *syn_flood_worker(void *arg)
```

### 2. Utilitários de Pacotes (`packet_utils.c`)
**Recursos:**
- Construção de pacotes raw
- Cálculo de checksum
- Validação e debug de pacotes

**Algoritmos Principais:**
```c
unsigned short calculate_ip_checksum(struct iphdr *ip_hdr)
unsigned short calculate_tcp_checksum(struct iphdr *ip_hdr, struct tcphdr *tcp_hdr)
int create_syn_packet(char *packet, const char *src_ip, ...)
```

### 3. Núcleo de Furtividade (`stealth_core.c`)
**Técnicas Implementadas:**
- Injeção de atraso
- Randomização de IPs
- Jitter no tráfego
- Ofuscação de pacotes

## Tipos de Ataques

### 1. Ataque Lento (ex: Slowloris)
**Comportamento:**
- Mantém conexões abertas
- Envia headers parciais
- Introduz atrasos aleatórios
- Imita tráfego legítimo

**Exemplo de Implementação:**
```python
def low_and_slow_attack(self):
    # Estabelece múltiplas conexões
    # Envia headers parciais incrementalmente
    # Insere atrasos aleatórios entre transmissões
```

### 2. Saturação (estilo DDoS)
**Vetores Incluídos:**
- SYN Flood
- UDP Flood
- ICMP Flood
- Flood de Requisições HTTP

**Exemplo de Implementação:**
```python
def saturation_attack(self):
    # Lança threads paralelas
    # 33% SYN, 33% UDP, 33% ICMP
```

### 3. Exploração de Vulnerabilidades
**Alvos de Ataque:**
- Reutilização de conexões TCP
- Injeção de cabeçalhos lentos
- Flood de sessões

## Configuração

### Exemplo `config/config.yaml`
```yaml
attack:
  slow:
    min_delay: 10
    max_delay: 15
    connection_timeout: 60
  saturation:
    syn_flood:
      enabled: true
      rate_limit: 1000
stealth:
  enabled: false
  min_delay: 100
  max_delay: 500
```

## Métricas de Performance

### Otimizações
- **Núcleo em C** para desempenho bruto
- **Pool de Threads** para concorrência
- **Sockets Raw** para controle total
- **Pool de Memória** para reutilização
- **Processamento em Lote** para throughput

### Benchmarks
- **Vazão**: >10.000 pacotes/segundo
- **Latência**: <1 ms/pacote
- **Uso de Memória**: <100MB (100 threads)
- **Carga de CPU**: <80% sob estresse

## Segurança e Evasão

### Técnicas de Evasão
1. Mutação e rotação de assinaturas
2. Randomização temporal de requisições
3. Criptografia e ofuscação de payloads
4. Spoofing de IP de origem
5. Manipulação dinâmica de headers e user-agent

### Recursos Anti-Detecção
- Técnicas para bypass de IDS/IPS
- Controle adaptativo de taxa
- Estratégias para evadir firewalls
- Simulação de tráfego legítimo

## Logging e Monitoramento

### Estrutura de Logs
```
logs/
├── engine.log       # Log global de operações
├── attack.log       # Atividades específicas de ataque
├── stealth.log      # Traços do modo furtivo
└── ioc.log          # Logs de geração de IoC
```

### Formato dos Logs
```
2024-01-01 12:00:00 - INFO - Engine inicializada
2024-01-01 12:00:01 - INFO - Ataque iniciado: modo lento
2024-01-01 12:00:02 - DEBUG - Thread 1 estabeleceu conexão
```

## Solução de Problemas

### Problemas Comuns
1. **Permissão Negada**
```bash
sudo setcap cap_net_raw+ep core/engine_core
```

2. **Dependências Ausentes**
```bash
sudo apt install build-essential libpcap-dev
```

3. **Falha ao Compilar Núcleo em C**
```bash
cd core && make clean && make
```

4. **Módulos Python Não Encontrados**
```bash
pip install -r requirements.txt
```

### Depuração
```bash
# Rodar em modo debug
python3 main.py --mode slow --target example.com --debug

# Logs em tempo real
tail -f logs/engine.log

# Verificação de processo
ps aux | grep engine
```

## Extensibilidade

### Adicionando Novos Ataques
1. Implemente a lógica em `python/engine.py`
2. Integre à CLI em `main.py`
3. Adicione opções em `config/config.yaml`
4. Documente em `examples/`

### Adicionando Payloads Customizados
1. Adicione o arquivo em `payloads/`
2. Defina a lógica de mutação em `payload_mutator.py`
3. Teste com `--payload-mutation`

### Gerando Novos IoCs
1. Estenda `ioc_generator.py`
2. Crie templates em `ioc/templates/`
3. Referencie em `config/config.yaml`

## Conformidade

### Padrões
- **STIX 2.1**: Estrutura de IoCs
- **Regras Sigma**: Modelagem de detecção
- **YARA**: Assinaturas binárias
- **RFC 791/793**: Conformidade IP/TCP

### Licenciamento
- **Licença MIT**: Software principal
- **CC-BY-SA**: Documentação
- **Aviso Legal**: Uso ético somente

## Roteiro de Desenvolvimento

### Versão 1.1
- [ ] Interface Web
- [ ] Suporte a protocolos adicionais
- [ ] Detecção de anomalias baseada em ML
- [ ] API RESTful

### Versão 1.2
- [ ] Implantação em cluster
- [ ] Capacidades nativas em nuvem
- [ ] Perfis furtivos avançados
- [ ] Telemetria em tempo real

### Versão 2.0
- [ ] Ataques automatizados com IA
- [ ] Emulação de zero-days
- [ ] Frameworks de persistência
- [ ] Compatibilidade multiplataforma
