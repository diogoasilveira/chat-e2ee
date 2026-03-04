import os
import asyncio
import websockets
import threading
import json
import sys
import time
import socket
import gnupg
import getpass

from chat_e2ee.util.logger import Logger
from chat_e2ee.core.key_policy import validate_destination, validate_origin, DEFAULT_POLICY

LOGGER = Logger(__name__).getLogger()
HOST = os.getenv("HOST")
PORT = int(os.getenv("PORT") or 65432)

# Validate required environment variables
if not HOST:
    raise RuntimeError("[!] Error: HOST environment variable is not set. Please run 'source config/native.env' first.")

queue = None
loop = None


async def manage_network(uri,
                         username,
                         gpg,
                         session_passphrase):
    global queue
    queue = asyncio.Queue()

    try:
        async with websockets.connect(uri) as ws:
            await ws.send(json.dumps(
                {
                    "type": "register",
                    "user": username
                }))
            LOGGER.info(f"\n[*] Connected to relay server as '{username}'.\n")

            async def listen():
                async for raw_message in ws:
                    data = json.loads(raw_message)
                    origin = data.get("origin")
                    payload = data.get("payload")

                    crypto = gpg.decrypt(
                        payload, passphrase=session_passphrase)

                    if crypto.ok:
                        texto_limpo = str(crypto)
                    else:
                        LOGGER.error(
                            f"\r\033[K[!] Failed to decrypt message from {origin}: {crypto.status}")
                        continue

                    LOGGER.info(f"\r\033[K[Message from {origin}]: {texto_limpo}")
                    sys.stdout.flush()

            async def process_queue():
                while True:
                    package = await queue.get()
                    await ws.send(json.dumps(package))

            await asyncio.gather(listen(), process_queue())

    except ConnectionRefusedError:
        LOGGER.error(f"[!] Error: Unable to connect to relay server. Make sure the server is running on {HOST}:{PORT}")
    except socket.gaierror as e:
        LOGGER.error(f"[!] Error: Failed to resolve hostname '{HOST}': {e}")
    except Exception as e:
        LOGGER.error(f"[!] Unexpected error in manage_network: {type(e).__name__}: {e}")


def start_network_thread(uri,
                         username,
                         gpg,
                         session_passphrase):
    """
    Função isolada que inicializa o loop assíncrono na thread secundária
    """
    global loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(manage_network(
        uri, username, gpg, session_passphrase))


def main():
    username = input("Enter your username: ").strip()
    session_passphrase = getpass.getpass("Enter your password: ")

    try:
        gpg = gnupg.GPG(homedir='.gnupg_chat_client')

    except Exception as e:
        LOGGER.error(f"[!] Error when starting PGP: {e}")
        return

    uri = f"ws://{HOST}:{PORT}"

    network_thread = threading.Thread(
        target=start_network_thread,
        args=(uri, username, gpg, session_passphrase),
        daemon=True)
    network_thread.start()

    while queue is None or loop is None:
        time.sleep(0.1)

    LOGGER.info("Send format -> recipient:message (ex: bob:hello)")

    while True:
        try:
            user_input = input("> ")

            if ":" in user_input:
                destination, text = user_input.split(":", 1)
                destination = destination.strip()
                text = text.strip()

                result_destination = validate_destination(gpg, destination)
                if not result_destination:
                    LOGGER.error(
                        f"\r\033[K[!] Key rejected by policy: {result_destination.reason}")
                    sys.stdout.flush()
                    continue

                result_origin = validate_origin(gpg, username)
                if not result_origin:
                    LOGGER.error(
                        f"\r\033[K[!] Key rejected by policy: {result_origin.reason}")
                    sys.stdout.flush()
                    continue

                crypto = gpg.encrypt(
                    text,
                    recipients=[destination],
                    sign=username,
                    passphrase=session_passphrase,
                    always_trust=True
                )

                if crypto.ok:
                    pgp_block = str(crypto)
                    package = {
                        "type": "message",
                        "origin": username,
                        "destination": destination,
                        "payload": pgp_block
                    }
                    loop.call_soon_threadsafe(queue.put_nowait,
                                              package)

                else:
                    LOGGER.error(
                        f"\r\033[K[!] PGP Error: Failed to encrypt the message.")
                    LOGGER.error(f"[GPG Details]: {crypto.status}")
                    sys.stdout.flush()

            else:
                LOGGER.error("[!] Invalid format. Use recipient:message")

        except KeyboardInterrupt as e:
            LOGGER.info("\nClosing connection securely...")
            session_passphrase = None
            break


if __name__ == "__main__":
    main()
