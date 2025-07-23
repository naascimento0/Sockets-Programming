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
├─ Block 0: 0-200KB     ├─ Chunk 0: 0-50KB
│                       ├─ Chunk 1: 50-100KB
│                       ├─ Chunk 2: 100-150KB
│                       └─ Chunk 3: 150-200KB
├─ Block 1: 200-400KB   └─ (4 chunks de 50KB)
├─ Block 2: 400-600KB   └─ (4 chunks de 50KB)
└─ Block 3: 600-800KB   └─ (4 chunks de 50KB)
```

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
# Arquivo de 10MB para teste
dd if=/dev/zero of=input/big_file.txt bs=1M count=10
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

1. **Arquivo Grande** (100MB):
```bash
dd if=/dev/zero of=input/big_file.txt bs=1M count=100
python client.py
```

2. **Múltiplos Clientes**:
```bash
# Execute vários clientes simultaneamente
python client.py &
python client.py &
python client.py &
```

3. **Teste de Falhas**:
- Interrompa o cliente durante a transferência (Ctrl+C)

### Verificação de Resultados

```bash
# Compare checksums
md5sum input/big_file.txt
md5sum output/server_received_*_big_file.txt

# Verifique logs coloridos no terminal
# Verde: ✅ Sucesso
# Vermelho: ❌ Erros
# Azul: 🔵 Blocos
# Ciano: 🔷 Coordenador
```

## ✨ Funcionalidades Implementadas

### Core Features
- ✅ **Transferência Paralela**: Até 4 blocos simultâneos
- ✅ **Verificação MD5**: Integridade garantida
- ✅ **Autenticação**: Sistema de credenciais com prioridades
- ✅ **Thread Safety**: Sincronização segura entre threads

### Interface e UX
- ✅ **Logs Coloridos**: ANSI colors para melhor visualização
- ✅ **Barra de Progresso**: TQDM para acompanhamento
- ✅ **Logs Estruturados**: Identificação clara por componente
- ✅ **Tratamento de Erros**: Mensagens informativas

### Robustez
- ✅ **Graceful Shutdown**: Encerramento controlado com SIGINT/SIGTERM
- ✅ **Timeout Handling**: Timeouts configuráveis por operação
- ✅ **Resource Cleanup**: Liberação adequada de recursos
- ✅ **Error Recovery**: Continuação mesmo com falhas parciais

### Organização
- ✅ **Modularização**: Código separado por responsabilidades
- ✅ **Configurabilidade**: Constantes facilmente ajustáveis
- ✅ **Output Directory**: Arquivos organizados em pasta separada
- ✅ **Logging Profissional**: Timestamps e níveis apropriados

## 🔮 Possíveis Melhorias Futuras

### Performance
- 🚧 **Compressão**: Implementar compressão de dados (gzip/lz4)
- 🚧 **Buffer Otimizado**: Ajuste dinâmico de tamanhos de chunk/bloco
- 🚧 **Connection Pooling**: Reutilização de conexões TCP
- 🚧 **Adaptive Parallelism**: Ajuste automático do número de threads

### Robustez
- 🚧 **Retry Logic**: Tentativas automáticas para blocos falhados
- 🚧 **Resume Transfer**: Continuação de transferências interrompidas
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
📝 Linhas de Código: ~800
🧵 Threads Máximas: 14 (4 client + 10 server)
📦 Tamanho do Bloco: 200KB
🔀 Paralelização: 4x
```
