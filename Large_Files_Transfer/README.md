# 🚀 Large Files Transfer System

Um sistema robusto de transferência de arquivos grandes através de TCP sockets com paralelização, verificação de integridade, recuperação de falhas e ajuste automático baseado no tamanho do arquivo.

## 📋 Descrição

Este projeto implementa um sistema cliente-servidor para transferência eficiente de arquivos grandes, abordando os principais desafios encontrados em transferências de rede:

### Desafios Abordados

1. **Transferência de Arquivos Grandes**: Divisão em blocos para evitar limitações de memória
2. **Paralelização Inteligente**: Múltiplas conexões com ajuste automático baseado no arquivo
3. **Verificação de Integridade**: Checksums MD5 para garantir integridade dos dados
4. **Recuperação de Falhas**: Capacidade de identificar e tratar blocos faltantes
5. **Autenticação**: Sistema de credenciais com prioridades
6. **Thread Safety**: Sincronização segura entre threads
7. **Otimização por Arquivo**: Ajuste automático de threads e tamanhos baseado no arquivo

### Arquitetura do Sistema

```
┌─────────────────┐                    ┌─────────────────┐
│     CLIENT      │                    │     SERVER      │
├─────────────────┤                    ├─────────────────┤
│  main()         │                    │  main()         │
│  ├─ Coordinator ├────────────────────┤  ├─ Queue       │
│  └─ N Threads   │ ←── Auto-sized ───┤  └─ ThreadPool  │
│      send_file_ │                    │     (optimized) │
│      block()    │                    │                 │
│  ├─ Optimizer   │                    │  ├─ Optimizer   │
│      by_size()  │                    │      by_size()  │
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

### Sistema de Ajuste Automático por Tamanho

O sistema ajusta automaticamente a configuração baseada no tamanho do arquivo:

| Tamanho do Arquivo | Threads | Tamanho do Bloco | Tamanho do Chunk |
|-------------------|---------|------------------|------------------|
| < 1MB (very_small) | 2       | 128KB           | 32KB            |
| 1-10MB (small)     | 3       | 200KB           | 50KB            |
| 10-100MB (medium)  | 4       | 512KB           | 64KB            |
| 100-500MB (large) | 6       | 1MB             | 128KB           |
| 500MB-1GB (very_large) | 8   | 2MB             | 256KB           |
| > 1GB (huge)      | 12      | 4MB             | 512KB           |

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

### 🎯 Sistema de Otimização Automática

O sistema ajusta automaticamente as configurações baseado no tamanho do arquivo:

#### Como Funciona

1. **Detecção do Arquivo**: O sistema analisa o tamanho do arquivo a ser transferido
2. **Categorização**: Classifica em 6 categorias (very_small até huge)
3. **Otimização**: Ajusta threads, blocos e chunks automaticamente
4. **Aplicação**: Usa as configurações otimizadas durante a transferência

#### Exemplo de Logs

```bash
[FILE OPTIMIZER] Otimização para big_file.txt (350.5MB, categoria: large)
[FILE OPTIMIZER] Threads: 6, Block: 1024KB, Chunk: 128KB
[FILE OPTIMIZER] Total de blocos: 342, Chunks por bloco: 8
```

### Configurações

As configurações são ajustadas automaticamente, mas você pode modificar os thresholds em `file_optimizer.py`:

**Configurações Automáticas**:
```python
# O sistema ajusta automaticamente:
# - Número de threads (2-12)
# - Tamanho do bloco (128KB-4MB)  
# - Tamanho do chunk (32KB-512KB)
```

**Configurações Manuais** (auth.py):
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

### 🆕 Otimização por Tamanho de Arquivo
- ✅ **Auto-sizing**: Ajuste automático baseado no tamanho do arquivo
- ✅ **Thread Optimization**: Número ideal de threads por categoria de arquivo
- ✅ **Block/Chunk Sizing**: Tamanhos otimizados para cada cenário
- ✅ **Category-based**: 6 categorias de arquivo com configurações específicas

## 🎯 Sistema de Otimização Baseada em Arquivo

### Como Funciona

O sistema analisa o tamanho do arquivo e ajusta automaticamente:

1. **Número de Threads**: De 2 (arquivos pequenos) até 12 (arquivos enormes)
2. **Tamanho do Bloco**: De 128KB até 4MB baseado no arquivo
3. **Tamanho do Chunk**: De 32KB até 512KB para melhor eficiência
4. **Categoria**: Classifica em very_small, small, medium, large, very_large, huge

### Lógica de Decisão

```python
# Categorização por tamanho
if file_size < 1MB:      category = 'very_small'  # 2 threads, 128KB blocks
elif file_size < 10MB:   category = 'small'       # 3 threads, 200KB blocks  
elif file_size < 100MB:  category = 'medium'      # 4 threads, 512KB blocks
elif file_size < 500MB:  category = 'large'       # 6 threads, 1MB blocks
elif file_size < 1GB:    category = 'very_large'  # 8 threads, 2MB blocks
else:                    category = 'huge'        # 12 threads, 4MB blocks
```

## 🔮 Possíveis Melhorias Futuras

### Performance
- 🚧 **Compressão**: Implementar compressão de dados (gzip/lz4)
- 🚧 **Buffer Otimizado**: Ajuste dinâmico de tamanhos de chunk/bloco
- 🚧 **Connection Pooling**: Reutilização de conexões TCP
- ✅ **Adaptive Sizing**: Ajuste automático baseado no tamanho do arquivo

### Otimização Avançada
- 🚧 **Network-aware**: Considerar latência e bandwidth da rede
- 🚧 **Hardware-aware**: Considerar CPU e memória disponível
- 🚧 **Dynamic Adjustment**: Ajuste em tempo real durante transferência

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
