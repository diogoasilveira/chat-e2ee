import asyncio
import websockets
import threading
import json
import sys
import time
import gnupg
import getpass

# Variáveis globais para comunicação segura entre as Threads
fila_de_envio = None
loop_assincrono = None

# ====================================================================
# ÁREA DO MEMBRO 4 (RECEBIMENTO E REDE EM SEGUNDO PLANO)
# ====================================================================
async def gerenciar_rede(uri, username, gpg, session_passphrase):
    global fila_de_envio
    fila_de_envio = asyncio.Queue()

    try:
        async with websockets.connect(uri) as ws:
            # 1. Registro inicial
            await ws.send(json.dumps({"tipo": "registro", "usuario": username}))
            print(f"\n[*] Conectado ao Relay E2EE como '{username}'.\n")

            # Tarefa A: Escutar o Servidor continuamente
            async def escutar_servidor():
                async for msg_raw in ws:
                    dados = json.loads(msg_raw)
                    origem = dados.get("origem")
                    payload_pgp = dados.get("payload_pgp")
                    
                    # Descriptografar e validar assinatura com GPG
                    resultado = gpg.decrypt(str(payload_pgp), passphrase=session_passphrase, always_trust=True)

                    if resultado.ok:
                        texto_limpo = str(resultado)
                    else:
                        texto_limpo = f"[Erro na descriptografia: {resultado.status}]"

                    # Imprime a mensagem recebida e recria o prompt de digitação
                    print(f"\r\033[K[Mensagem de {origem}]: {texto_limpo}")
                    print("> ", end="")
                    sys.stdout.flush()

            # Tarefa B: Enviar mensagens que estão na fila
            async def processar_fila():
                while True:
                    pacote = await fila_de_envio.get()
                    await ws.send(json.dumps(pacote))

            # Executa a escuta e o envio simultaneamente na thread assíncrona
            await asyncio.gather(escutar_servidor(), processar_fila())
            
    except ConnectionRefusedError:
        print("\n[!] Erro: Não foi possível conectar ao Servidor Relay.")

def iniciar_thread_da_rede(uri, username, gpg, session_passphrase):
    """Função isolada que inicializa o loop assíncrono na thread secundária"""
    global loop_assincrono
    loop_assincrono = asyncio.new_event_loop()
    asyncio.set_event_loop(loop_assincrono)
    loop_assincrono.run_until_complete(gerenciar_rede(uri, username, gpg, session_passphrase))

# ====================================================================
# ÁREA DO MEMBRO 3 (ENVIO E INTERFACE PRINCIPAL)
# ====================================================================
def main():
    print("=== CHAT CLI E2EE PGP ===")
    username = input("Digite seu nome de usuário: ").strip()
    
    # Captura a senha de forma invisível no terminal
    session_passphrase = getpass.getpass("Digite sua senha do PGP: ")
    
    try:
        gpg = gnupg.GPG(gnupghome='.gnupg_chat_client')
    except Exception as e:
        print(f"[!] Erro ao inicializar o GPG: {e}")
        return
    
    uri = "ws://localhost:8765"

    # Inicia a Rede em uma Thread separada (Modo Daemon para fechar junto com o app)
    thread_rede = threading.Thread(target=iniciar_thread_da_rede, args=(uri, username, gpg, session_passphrase), daemon=True)
    thread_rede.start()

    # Aguarda um milissegundo para a fila assíncrona ser criada
    while fila_de_envio is None or loop_assincrono is None:
        time.sleep(0.1)

    print("Formato de envio -> destinatário:mensagem (ex: bob:olá)")
    
    # Loop de Interface (bloqueante)
    while True:
        try:
            # O terminal para aqui esperando o usuário digitar
            entrada = input("> ")
            
            if ":" in entrada:
                destino, texto = entrada.split(":", 1)
                destino = destino.strip()
                texto = texto.strip()
                
                # 1 e 2 e 3: Assinar com a chave de 'username' e Criptografar para 'destino'
                # O python-gnupg faz as duas operações de uma só vez se passarmos o parâmetro 'sign'
                criptograma = gpg.encrypt(
                    texto,
                    recipients=[destino],       # Chave Pública do Destinatário
                    sign=username,              # Chave Privada do Remetente (para assinatura)
                    passphrase=session_passphrase, # Desbloqueia a Chave Privada em memória
                    always_trust=True           # Permite usar chaves importadas (ajustar conforme a Web of Trust do Membro 2)
                )
                
                if criptograma.ok:
                    bloco_pgp = str(criptograma)
                    
                    pacote = {
                        "tipo": "mensagem",
                        "origem": username,
                        "destino": destino,
                        "payload_pgp": bloco_pgp
                    }
                    # Injeta o pacote na fila assíncrona de forma segura entre as threads
                    loop_assincrono.call_soon_threadsafe(fila_de_envio.put_nowait, pacote)
                else:
                    # Tratamento de erros comuns: falta da chave do destinatário ou palavra-passe errada
                    print(f"\r\033[K[!] Erro PGP: Não foi possível encriptar a mensagem.")
                    print(f"[Detalhes do GPG]: {criptograma.status}")
                    print("> ", end="")
                    sys.stdout.flush()
                    
            else:
                print("[!] Formato inválido. Use destinatário:mensagem")
                
        except KeyboardInterrupt: # Captura o Ctrl+C
            print("\nEncerrando conexão de forma segura...")
            session_passphrase = None
            break

if __name__ == "__main__":
    main()