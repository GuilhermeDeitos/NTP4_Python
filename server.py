import socket
import struct
import time
from cryptography.hazmat.primitives import hashes, hmac
from dotenv import load_dotenv
from os import getenv


NTP_ADDR = 'localhost'
NTP_PORT = 12345
NTP_EPOCH = 2208988800  # 1970-1900 em segundos (tempo unix)

def resposta_ntp(receiveTimestamp):
    leapIndicator = 0
    versionNumber = 4
    mode = 4  # Modo 4 = Server
    leapIndicator_version_mode = (leapIndicator << 6) | (versionNumber << 3) | mode

    stratum = 1  # Estrato 1, pois é um servidor primário
    poll = 4 
    precision = -6

    rootDelay = 0
    rootDispersion = 0
    referenceId = 0x4C4f434C  # LOCL em ASCII, para indicar que é um servidor local

    referenceTimestamp = int(time.time() + NTP_EPOCH) << 32
    originateTimestamp = receiveTimestamp  # Timestamp original do cliente
    transmitTimestamp = int(time.time() + NTP_EPOCH) << 32
    print(f"Originate Timestamp: {originateTimestamp}")
    print(f"Transmit Timestamp: {transmitTimestamp}")
    print(f"referenceTimestamp Timestamp: {referenceTimestamp}")

    return struct.pack(
        "!B B b b I I I Q Q Q Q",  # 48 bytes
        leapIndicator_version_mode,
        stratum,
        poll,
        precision,
        int(rootDelay * (2**16)),
        int(rootDispersion * (2**16)),
        referenceId,
        referenceTimestamp,
        originateTimestamp,
        receiveTimestamp,
        transmitTimestamp
    )

from cryptography.hazmat.primitives import hashes, hmac

def criptografar_resposta(key, resposta):
    try:
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(resposta)
        hmac_digest = h.finalize()
        
        return resposta + hmac_digest
    except Exception as e:
        raise ValueError(f"Erro ao criptografar a mensagem: {e}")

def main():
    try:
        load_dotenv()
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind((NTP_ADDR, NTP_PORT))
        print(f'Servidor NTP iniciado na porta {NTP_PORT}')
        
        while True:
            data, address = server.recvfrom(1024)
            print(f"Recebido de {address}")
            print(f"Data: {data}")

            currentTime = time.time() + NTP_EPOCH
            receiveTimestampHigh = int(currentTime)
            receiveTimestampLow = int((currentTime - receiveTimestampHigh) * (2**32))
            receiveTimestamp = (receiveTimestampHigh << 32) | receiveTimestampLow

            resposta = resposta_ntp(receiveTimestamp)
            key = getenv("KEY").encode()
            if key != None:
                server.sendto(criptografar_resposta(key, resposta), address)
            else:
                print("Falha ao carregar a chave 👍🤣")
    except Exception as e:
        print(f"Erro: {e}")

if __name__ == "__main__":
    main()