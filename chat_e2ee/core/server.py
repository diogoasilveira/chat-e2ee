import os
import asyncio
import json
import websockets

from chat_e2ee.util.logger import Logger

LOGGER = Logger(__name__).getLogger()
PORT = int(os.getenv("PORT"))

connected_clients = {}


async def manage_connection(websocket):
    """
    Função (corrotina) que gerencia o ciclo de vida de CADA conexão individual.
    O asyncio cria uma instância dessa função para cada cliente que conecta.
    """
    username = None
    try:
        async for raw_message in websocket:
            try:
                data = json.loads(raw_message)
                type = data.get("type")

                match type:
                    case "register":
                        username = data.get("user")
                        if username:
                            connected_clients[username] = websocket
                            LOGGER.info(f"[+] {username} connected.")

                    case "message" | "exchange_keys":
                        origin = data.get("origin") 
                        destination = data.get("destino")  # "destination"

                        if destination in connected_clients:
                            ws_destination = connected_clients[destination]
                            await ws_destination.send(raw_message)
                            LOGGER.info(
                                f"[*] Routing from {origin} to {destination}")

                        else:
                            error = {
                                "type": "system",
                                "message": f"User {destination} is offline or does not exist."
                            }
                            await websocket.send(json.dumps(error))

            except json.JSONDecodeError:
                LOGGER.error(f"[!] Invalid package received (not JSON).")

    except websockets.exceptions.ConnectionClosed as e:
        LOGGER.error(f"[!] {e}")

    except Exception as e:
        LOGGER.error(f"[!] Unexpected error: {e}")

    finally:
        if username and username in connected_clients:
            del connected_clients[username]
            print(f"[-] {username} disconnected.")


async def main():
    LOGGER.info(f"Starting relay server on port {PORT}...")
    LOGGER.info("Waiting for connections...")

    async with websockets.serve(manage_connection,
                                "localhost",
                                PORT):
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())
