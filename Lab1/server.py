from socket import * # Importar módulo de socket
import sys  # Para encerrar o programa

# Criar o socket do servidor
serverSocket = socket(AF_INET, SOCK_STREAM)

# Preparar o socket de servidor
# Fill in start
serverSocket.bind(('', 6789)) # Vincula a todas as interfaces na porta 6789
serverSocket.listen(1) # Escuta até 1 conexão na fila
# Fill in end

while True:
    # Estabelecer a conexão
    print('Ready to serve...')
    print(f"Type on browser: http://{gethostbyname(gethostname())}:6789/index.html")
    # Fill in start
    connectionSocket, addr = serverSocket.accept() # Aceita conexão do cliente
    # Fill in end

    try:
        # Receber a requisição HTTP do cliente
        # Fill in start
        message = connectionSocket.recv(1024).decode()
        # Fill in end 
        
        # Extrair o nome do arquivo da requisição HTTP
        # Fill in start
        filename = message.split()[1] # O nome do arquivo está após o método GET (ex.: GET /HelloWorld.html HTTP/1.1)
        filename = filename.lstrip('/') # Remove a barra inicial do nome do arquivo
        # Fill in end

        # Abrir e ler o arquivo solicitado
        # Fill in start
        f = open(filename, 'r')
        outputdata = f.read()
        f.close() # Fecha o arquivo
        # Fill in end

        # Enviar o cabeçalho HTTP 200 OK
        # Fill in start
        connectionSocket.send("HTTP/1.1 200 OK\r\n\r\n".encode())  # Envia o cabeçalho de sucesso
        # Fill in end
        
        # Enviar o conteúdo do arquivo solicitado
        for i in range(0, len(outputdata)):
            connectionSocket.send(outputdata[i].encode())  # Envia cada caractere do arquivo
        connectionSocket.send("\r\n".encode())  # Envia nova linha final
        connectionSocket.close()  # Fecha o socket da conexão

    except IOError:
        # Enviar mensagem de erro 404 Not Found
        # Fill in start
        connectionSocket.send("HTTP/1.1 404 Not Found\r\n\r\n".encode())  # Cabeçalho de erro
        connectionSocket.send("<html><head></head><body><h1>404 Not Found</h1></body></html>\r\n".encode())  # Corpo do erro
        # Fill in end
        
        # Fechar o socket do cliente
        # Fill in start
        connectionSocket.close()  # Fecha o socket da conexão
        # Fill in end
    
    # O servidor continua rodando, então não fechamos serverSocket aqui
    
# Fechar o socket do servidor (nunca alcançado devido ao loop infinito)
serverSocket.close()