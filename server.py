import asyncio
import json
import websockets

# Tabela de roteamento global: { "username": objeto_websocket }
clientes_conectados = {}

async def gerenciar_conexao(websocket):
    """
    Função (corrotina) que gerencia o ciclo de vida de CADA conexão individual.
    O asyncio cria uma instância dessa função para cada cliente que conecta.
    """
    username = None
    try:
        # Loop infinito ouvindo as mensagens que chegam deste websocket
        async for mensagem_raw in websocket:
            try:
                # Transforma a string JSON recebida em um dicionário Python
                dados = json.loads(mensagem_raw)
                tipo = dados.get("tipo")

                # 1. Fase de Registro
                if tipo == "registro":
                    username = dados.get("usuario")
                    if username:
                        clientes_conectados[username] = websocket
                        print(f"[+] {username} conectou. Usuários online: {list(clientes_conectados.keys())}")

                # 2. Fase de Roteamento Zero-Knowledge
                elif tipo == "mensagem" or tipo == "troca_chave":
                    origem = dados.get("origem")
                    destino = dados.get("destino")
                    
                    if destino in clientes_conectados:
                        # Repassa o pacote EXATAMENTE como chegou. 
                        # O servidor não lê e não se importa com o "payload_pgp".
                        ws_destino = clientes_conectados[destino]
                        await ws_destino.send(mensagem_raw)
                        print(f"[*] Roteando de {origem} para {destino}")
                    else:
                        # Se o destino não existe, avisa o remetente
                        erro = {
                            "tipo": "sistema", 
                            "mensagem": f"Usuário '{destino}' está offline ou não existe."
                        }
                        await websocket.send(json.dumps(erro))

            except json.JSONDecodeError:
                print(f"[!] Erro: Pacote inválido recebido (não é JSON).")

    except websockets.exceptions.ConnectionClosed:
        # É normal cair aqui quando o cliente fecha o terminal abruptamente
        pass
    except Exception as e:
        print(f"[!] Erro inesperado: {e}")
    finally:
        # Fase de Limpeza: Remove o usuário da tabela quando ele desconecta
        if username and username in clientes_conectados:
            del clientes_conectados[username]
            print(f"[-] {username} desconectou.")

async def main():
    porta = 8765
    print(f"Iniciando Servidor Relay E2EE na porta {porta}...")
    print("Aguardando conexões...")
    
    # Inicia o servidor e o mantém rodando indefinidamente
    async with websockets.serve(gerenciar_conexao, "localhost", porta):
        await asyncio.Future()  # Roda para sempre

if __name__ == "__main__":
    # Ponto de entrada do programa assíncrono
    asyncio.run(main())