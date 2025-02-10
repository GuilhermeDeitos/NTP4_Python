def carregar_chave_ntp():
    try:
        # /etc/ntp.keys
        with open("/etc/ntp.keys", "r") as f:
            for linha in f:
                partes = linha.strip().split()
                if len(partes) == 3 and partes[1] == "SHA256":
                    return int(partes[0]), partes[2].encode()
        return None, None
    except FileNotFoundError:
        print("Arquivo ntp.keys não encontrado.")
        return None, None
