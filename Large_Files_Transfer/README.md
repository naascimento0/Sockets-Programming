# 🚀 Large Files Transfer System

Um sistema robusto de transferência de arquivos grandes através de TCP sockets com paralelização, verificação de integridade e recuperação de falhas.

## 📋 Descrição

Este projeto implementa um sistema cliente-servidor para transferência eficiente de arquivos grandes, abordando os principais desafios encontrados em transferências de rede:

### Desafios Abordados

1. **Transferência de Arquivos Grandes**: Divisão em blocos para evitar limitações de memória
2. **Paralelização**: Múltiplas conexões simultâneas para maximizar throughput
3. **Verificação de Integridade**: Checksums MD5 para garantir integridade dos dados
4. **Recuperação de Falhas**: Capacidade de identificar e tratar blocos faltantes
5. **Autenticação**: Sistema de credenciais com prioridades
6. **Thread Safety**: Sincronização segura entre threads

### Arquitetura do Sistema

```
┌─────────────────┐                    ┌─────────────────┐
│     CLIENT      │                    │     SERVER      │
├─────────────────┤                    ├─────────────────┤
│  main()         │                    │  main()         │
│  ├─ Coordinator ├────────────────────┤  ├─ Queue       │
│  └─ 4x Threads  │                    │  └─ ThreadPool  │
│      send_file_ │                    │     (10 workers)│
│      block()    │                    │                 │
└─────────────────┘                    └─────────────────┘
```

### Fluxo de Transferência

```
CLIENT                                 SERVER
  │                                      │
  ├─ 1. Coordinator Connection          ├─ handle_file_coordinator()
  │   └─ FILE_START@metadata            │   └─ Initialize transfer metadata
  │                                     │
  ├─ 2. Parallel Block Transfers        ├─ handle_block_transfer() x4
  │   ├─ Thread 1: Block 0              │   ├─ Receive chunks (50KB each)
  │   ├─ Thread 2: Block 1              │   ├─ Validate & store blocks
  │   ├─ Thread 3: Block 2              │   └─ Update progress counters
  │   └─ Thread 4: Block 3              │
  │                                     │
  ├─ 3. Transfer Complete Signal        ├─ assemble_file_from_blocks()
  │   └─ TRANSFER_COMPLETE              │   ├─ Reconstruct original file
  │                                     │   ├─ Handle missing blocks
  │                                     │   └─ Save to output/ directory
  │                                     │
  └─ 4. Integrity Verification          └─ MD5 checksum verification
      └─ Receive INTEGRITY_OK/FAILED       └─ Compare checksums
```

### Estrutura de Dados

```
Arquivo Original (2MB)
├─ Block 0: 0-200KB     ├─ Chunk 0: 0-50KB    ← ACK/NACK
│                       ├─ Chunk 1: 50-100KB  ← ACK/NACK
│                       ├─ Chunk 2: 100-150KB ← ACK/NACK
│                       └─ Chunk 3: 150-200KB ← ACK/NACK
├─ Block 1: 200-400KB   └─ (4 chunks de 50KB)
├─ Block 2: 400-600KB   └─ (4 chunks de 50KB)
└─ Block 3: 600-800KB   └─ (4 chunks de 50KB)
```

### Sistema NACK (Negative Acknowledgment)

O sistema implementa um mecanismo robusto de detecção e correção de erros:

```
Cliente                                 Servidor
  │                                      │
  ├─ Send Chunk (50KB)                   ├─ Receive & Validate
  │                                      │   ├─ Size check
  │                                      │   └─ Data integrity
  │                                      │
  └─ Wait for Response                   └─ Send Response
                                             ├─ ACK (✅ OK)
                                             └─ NACK (❌ Error)

Em caso de NACK:
  ├─ Log warning com posição do erro
  ├─ Volta file pointer para chunk anterior
  ├─ Reenvia chunk automaticamente
  └─ Conta tentativas (máx 5 por bloco)
```

**Cenários que geram NACK:**
- **Chunk vazio**: Servidor não recebe dados
- **Tamanho incorreto**: Chunk menor que esperado
- **Timeout de rede**: Perda de pacotes TCP
- **Corrupção de dados**: Dados inconsistentes

## 🛠️ Tecnologias Utilizadas

- **Python 3.7+**
- **Socket Programming**: TCP para comunicação cliente-servidor
- **Threading**: `ThreadPoolExecutor` para paralelização
- **Hashlib**: MD5 para verificação de integridade
- **TQDM**: Barras de progresso para UX
- **Collections**: `defaultdict` para estruturas de dados thread-safe
- **Queue**: Sistema de prioridades para clientes
- **ANSI Colors**: Interface colorida no terminal

## 🚀 Como Executar

### Requisitos

- Python 3.7 ou superior
- Bibliotecas Python (instalar com pip):

```bash
pip install tqdm
```

### Preparação do Ambiente

1. **Clone/baixe o projeto**:
```bash
cd Large_Files_Transfer
```

2. **Crie a estrutura de diretórios**:
```bash
mkdir -p input output
```

3. **Crie um arquivo de teste**:
```bash
python3 create_big_file.py
```

### Execução

1. **Inicie o servidor** (Terminal 1):
```bash
python server.py
```

2. **Execute o cliente** (Terminal 2):
```bash
python client.py
```

### Configurações

Edite as constantes nos arquivos para ajustar:

**client.py / server.py**:
```python
SERVER = "localhost"          # IP do servidor
PORT = 4455                   # Porta de comunicação
CHUNK_SIZE = 1024 * 50        # 50KB por chunk
BLOCK_SIZE = 1024 * 200       # 200KB por bloco
MAX_PARALLEL_BLOCKS = 4       # Threads simultâneas
```

**auth.py**:
```python
CREDENTIALS = {
    "admin": {"password": "admin123", "priority": 1},
    "user1": {"password": "password1", "priority": 0}
}
```

## 🧪 Como Testar

### Teste Básico
```bash
# Terminal 1
python server.py

# Terminal 2
python client.py
```

### Testes de Stress

1. **Arquivo Grande**:
Modifique o script `create_big_file.py` para gerar um arquivo maior, depois execute:
```python
python3 create_big_file.py
```

2. **Múltiplos Clientes**:
```bash
# Execute vários clientes simultaneamente
python client.py &
python client.py &
python client.py &
```

3. **Teste de Falhas**:
- Interrompa o cliente ou o servidor durante a transferência (Ctrl+C)

4. **Teste do Sistema NACK**:
```bash
# Para demonstrar a importância do tratamento NACK,
# Descomente as linhas 160-163 no client.py
# Observe como o arquivo final terá checksum diferente

# Linhas para descomentar:
# logging.error(f"{Colors.RED}[Block {block_id}]{Colors.RESET} Aborting block due to NACK (test mode)")
# client.close()
# return False
```

## ✨ Funcionalidades Implementadas

### Core Features
- ✅ **Transferência Paralela**: Até 4 blocos simultâneos
- ✅ **Verificação MD5**: Integridade garantida
- ✅ **Autenticação**: Sistema de credenciais com prioridades
- ✅ **Thread Safety**: Sincronização segura entre threads
- ✅ **NACK Handling**: Detecção e correção automática de chunks corrompidos
- ✅ **Retry Logic**: Reenvio automático de blocos com falhas

### Interface e UX
- ✅ **Logs Coloridos**: ANSI colors para melhor visualização
- ✅ **Barra de Progresso**: TQDM para acompanhamento
- ✅ **Logs Estruturados**: Identificação clara por componente
- ✅ **Tratamento de Erros**: Mensagens informativas
- ✅ **Transfer Statistics**: Métricas detalhadas de qualidade da transferência
- ✅ **NACK Monitoring**: Visualização de chunks rejeitados e retry automático

### Robustez
- ✅ **Graceful Shutdown**: Encerramento controlado com SIGINT/SIGTERM
- ✅ **Resource Cleanup**: Liberação adequada de recursos
- ✅ **Error Recovery**: Continuação mesmo com falhas parciais
- ✅ **Block Retry System**: Até 3 tentativas por bloco com backoff
- ✅ **Chunk Validation**: Verificação individual de chunks (50KB cada)
- ✅ **Signal Handlers**: Shutdown gracioso em cliente e servidor

### Organização
- ✅ **Modularização**: Código separado por responsabilidades
- ✅ **Configurabilidade**: Constantes facilmente ajustáveis
- ✅ **Output Directory**: Arquivos organizados em pasta separada
- ✅ **Logging**: Timestamps e níveis apropriados

## 🔮 Possíveis Melhorias Futuras

### Performance
- 🚧 **Compressão**: Implementar compressão de dados (gzip/lz4)
- 🚧 **Buffer Otimizado**: Ajuste dinâmico de tamanhos de chunk/bloco
- 🚧 **Connection Pooling**: Reutilização de conexões TCP
- 🚧 **Adaptive Parallelism**: Ajuste automático do número de threads

### Robustez
- 🚧 **Checksum Parcial**: Verificação por bloco (não apenas arquivo completo)
- 🚧 **Rate Limiting**: Controle de velocidade de transferência

### Segurança
- 🚧 **Criptografia**: TLS/SSL para dados em trânsito
- 🚧 **Token Authentication**: JWT ao invés de credenciais em texto
- 🚧 **File Validation**: Verificação de tipo/tamanho de arquivo
- 🚧 **Access Control**: Permissões por usuário/diretório

### Funcionalidades
- 🚧 **Web Interface**: Dashboard web para monitoramento
- 🚧 **REST API**: Endpoints HTTP para integração
- 🚧 **File Browser**: Interface para navegação de arquivos
- 🚧 **Transfer History**: Histórico de transferências
---

## 📊 Estatísticas do Projeto

```
📁 Arquivos: 6
📝 Linhas de Código: ~1200
🧵 Threads Máximas: 14 (4 client + 10 server)
📦 Tamanho do Bloco: 200KB
🔀 Paralelização: 4x
🔄 Sistema NACK: Retry automático de chunks
🛡️ Max Retries: 3 tentativas por bloco
```

### Funcionalidades Avançadas Implementadas

- **🔴 NACK System**: Detecção e correção automática de chunks corrompidos
- **🟡 Graceful Shutdown**: Signal handlers (SIGINT/SIGTERM) em cliente e servidor  
- **🟢 Transfer Statistics**: Métricas detalhadas de qualidade (NACKs, retries, falhas)
- **🔵 Chunk Validation**: Verificação individual de integridade por chunk
- **🟣 Auto-retry Logic**: Até 3 tentativas por bloco com delays progressivos
