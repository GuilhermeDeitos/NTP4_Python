import socket
import struct, time
from cryptography.hazmat.primitives import hashes, hmac
from dotenv import load_dotenv
from os import getenv

print("Caso não deseje trocar nenhum dos valores padrões, apenas aperte Enter.")
NTP_SERVER = str(input("Deseja mudar o servidor? [localhost] "))  # Endereço do servidor NTP local
if NTP_SERVER == "": 
    NTP_SERVER = "localhost"

NTP_PORT = str(input("Deseja a mudar porta? [12345] "))
if NTP_PORT == "":
    NTP_PORT = 12345
else:
    NTP_PORT = int(NTP_PORT)
NTP_EPOCH = 2208988800  # 1970-1900 em segundos (tempo unix)

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

    # Inicializando os timestamps como 0
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
    """
    Extrai os timestamps de recepção (t2) e transmissão (t3) do pacote NTP recebido.
    """
    descompactado = struct.unpack("!B B b b I I I Q Q Q Q", data)

    t2 = (descompactado[8] >> 32) + (descompactado[8] & 0xFFFFFFFF) / (2**32)  # Recebido
    t3 = (descompactado[9] >> 32) + (descompactado[9] & 0xFFFFFFFF) / (2**32)  # Transmitido
    return t2, t3

def calc_offset(t1, t2, t3, t4) -> tuple:
    offset = ((t2 - t1) + (t3 - t4)) / 2
    delay = (t4 - t1) - (t3 - t2)
    return offset, delay

def validar_hmac(key, mensagem, hmac_recebido):
    try:
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(mensagem)
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
        
        t1 = time.time() + NTP_EPOCH
        key = getenv("KEY").encode()
        # Criar e enviar o pacote NTP
        data = criar_req_ntp()
        client.sendto(data, (NTP_SERVER, NTP_PORT))
        
        # Receber o pacote NTP de resposta
        data, address = client.recvfrom(1024)
        if(len(data) != 80 and NTP_SERVER == "localhost"):
            raise ValueError(f"Pacote NTP inválido. O pacote deve ter 80 bytes mas tem {len(data)} bytes.")

        pacote_ntp = data[:48]
        hmac_recebido = data[48:]
        
        key = getenv("KEY").encode()
        if(NTP_SERVER == "localhost"):
            if validar_hmac(key, pacote_ntp, hmac_recebido) == False:
                return

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