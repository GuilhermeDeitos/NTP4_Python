import socket
import struct, time
from cryptography.hazmat.primitives import hashes, hmac
from dotenv import load_dotenv
from os import getenv

print("Caso não deseje trocar nenhum dos valores padrões, apenas aperte Enter.")

NTP_SERVER = str(input("Deseja mudar o servidor? [localhost] ")) or "localhost"
NTP_PORT = input("Deseja a mudar porta? [123] ") or 123
NTP_EPOCH = 2208988800  # 1970-1900 em segundos (tempo unix)
HMAC_SIZE = 32

def carregar_chave_ntp():
    try:
        with open("/etc/ntp.keys", "r") as f:
            for linha in f:
                partes = linha.strip().split()
                if len(partes) == 3 and partes[1] == "SHA256":
                    return int(partes[0]), partes[2].encode()
        return None, None
    except FileNotFoundError:
        print("Arquivo ntp.keys não encontrado.")
        return None, None

def criar_req_ntp():
    leapIndicator = 0
    version = 4
    mode = 3  # Modo 3 é o modo do cliente
    leapIndicator_version_mode = (leapIndicator << 6) | (version << 3) | mode

    stratum = 0
    poll = 4
    precision = -6

    rootDelay = 0
    rootDispersion = 0
    referenceId = 0

    referenceTimestamp = 0
    originateTimestamp = int(time.time() + NTP_EPOCH)
    receiveTimestamp = 0

    # Timestamp atual
    currentTime = time.time() + NTP_EPOCH
    transmitTimestampHigh = int(currentTime)
    transmitTimestampLow = int((currentTime - transmitTimestampHigh) * (2**32))
    transmitTimestamp = (transmitTimestampHigh << 32) | transmitTimestampLow

    return struct.pack(
        "!B B b b I I I Q Q Q Q", 
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

def extract_timestamps_from_package(data):
    descompactado = struct.unpack("!B B b b I I I Q Q Q Q", data)

    t2 = (descompactado[8] >> 32) + (descompactado[8] & 0xFFFFFFFF) / (2**32)  # Recebido
    t3 = (descompactado[9] >> 32) + (descompactado[9] & 0xFFFFFFFF) / (2**32)  # Transmitido
    return t2, t3

def calc_offset(t1, t2, t3, t4) -> tuple:
    offset = ((t2 - t1) + (t3 - t4)) / 2
    delay = (t4 - t1) - (t3 - t2)
    return offset, delay

def validar_hmac(chave_ntp, pacote_ntp, hmac_recebido):
    try:
        h = hmac.HMAC(chave_ntp, hashes.SHA256())
        h.update(pacote_ntp)
        h.verify(hmac_recebido)  # Lança uma exceção se o HMAC não for válido
        print("HMAC verificado com sucesso.")
        return True
    except Exception as e:
        print("Cliente não autorizado para sincronização:", e)
        return False       
    
def main():
    try:
        load_dotenv()
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(5)
        
        chave_id, chave_ntp = carregar_chave_ntp()
        if chave_ntp is None:
            print("Nenhuma chave NTP encontrada. A resposta não será autenticada.")

        # Criar e enviar o pacote NTP
        data = criar_req_ntp()
        t1 = time.time() + NTP_EPOCH
        client.sendto(data, (NTP_SERVER, NTP_PORT))
        
        data, address = client.recvfrom(1024)

        if len(data) < 48 + HMAC_SIZE:
            raise ValueError("Pacote recebido é menor do que o esperado.")

        pacote_ntp = data[:48]
        hmac_recebido = data[48:]

        if not validar_hmac(chave_ntp, pacote_ntp, hmac_recebido) and chave_ntp is not None:
            raise ValueError("HMAC inválido! O servidor pode não ser confiável.")
 
        t4 = time.time() + NTP_EPOCH
        t2, t3 = extract_timestamps_from_package(pacote_ntp)

        print(f"t1: {t1}")
        print(f"t2: {t2}")
        print(f"t3: {t3}")
        print(f"t4: {t4}")

        offset, delay = calc_offset(t1, t2, t3, t4)
        server_time = t4 + offset - NTP_EPOCH  # Ajustar para a época Unix
        print(f"server_time (segundos desde a época Unix): {server_time}")

        if server_time < 0:
            raise ValueError("server_time é um valor negativo, o que é inválido.")

        local_time = time.localtime(server_time)
        horario_ajustado = time.strftime('%Y-%m-%d %H:%M:%S', local_time)        
        print(f"Offset: {offset}s")
        print(f"Delay: {delay}s")
        print(f"Server time: {server_time}")
        print(f"Ajustado: {horario_ajustado}")
    except Exception as e:
        print(f"Erro: {e}")     

if __name__ == "__main__":
    main()