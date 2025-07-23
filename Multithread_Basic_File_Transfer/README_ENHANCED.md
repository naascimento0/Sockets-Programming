# Servidor de Arquivos Multithread com Download Paralelo - DEMO

## Como usar:

### 1. Inicie o servidor:

```bash
python server.py
```

### 2. Inicie o cliente:

```bash
python client.py
```

### 3. Faça login:

```
> LOGIN admin admin123
```

### 4. Comandos disponíveis:

#### Listar arquivos:

```
> LIST
```

#### Obter informações de um arquivo:

```
> FILE_INFO test_file.txt
```

#### Download paralelo:

```
> DOWNLOAD_PARALLEL test_file.txt 4
```

#### Ver informações do usuário:

```
> WHOAMI
```

### 5. Usuários de teste:

- **admin/admin123** (role: admin, priority: 1) - Pode deletar arquivos
- **user1/pass123** (role: user, priority: 2) - Pode deletar arquivos
- **guest/guest123** (role: guest, priority: 3) - Apenas leitura

## Funcionalidades implementadas:

✅ **Autenticação de usuários**
✅ **Controle de acesso baseado em roles**
✅ **Download paralelo com múltiplas threads**
✅ **Divisão de arquivos em chunks**
✅ **Verificação de integridade (MD5 checksum)**
✅ **Sistema de prioridades para usuários**
✅ **Tratamento robusto de erros**
✅ **Logs estruturados**

## Arquitetura:

### Download Paralelo:

1. Cliente solicita informações do arquivo (tamanho, checksum, chunks)
2. Cliente cria múltiplas conexões para baixar chunks em paralelo
3. Cada thread baixa um chunk específico
4. Cliente reconstitui o arquivo juntando os chunks
5. Verificação de integridade com checksum MD5

### Sistema de Autenticação:

- Usuários devem fazer login antes de acessar recursos
- Diferentes níveis de permissão (admin, user, guest)
- Sessões ativas são rastreadas pelo servidor

### Controle de Qualidade:

- Verificação de integridade com MD5
- Retry automático para chunks que falharam
- Logging detalhado de todas as operações
