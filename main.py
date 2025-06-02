from HttpHandler import HttpHandler
from ECCOperator import ECC_P256
from TCPHandler import TCPHandler

if __name__ == "__main__":
    TCP = TCPHandler()
    ecc1 = ECC_P256()
    http_sender = HttpHandler()
    server_pk_pem = ecc1.read_pk_pem()
    while True:
        temp = TCP.get_temperature()
        print(f"溫度：{temp}")
        if temp != None:
            encrypted_message = ecc1.asymmetric_encryption(str(temp).encode(),server_pk_pem)
            http_sender.send_encrypted_message(encrypted_message)