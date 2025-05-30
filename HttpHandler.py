from ECCOperator import ECC_P256
import requests
import json


function_list = {"send_encrypted_message":"decrypt"}
time_out = 5

class HttpHandler:

    def __init__(self,server_url = "http://127.0.0.1:5000/"):
        self.server_url = str(server_url)
        
    def send_encrypted_message(self,encrypted_message):
        try:
            url = self.server_url+function_list["send_encrypted_message"]
            payload = {"encrypted_packet":encrypted_message}
            resp = requests.post(url,json=payload,timeout=time_out)
            resp.raise_for_status()
            data = resp.json()
        except requests.exceptions.Timeout:
            print("Error time out")
        except requests.exceptions.ConnectionError:
            print("Connect Error")
        except requests.exceptions.HTTPError:
            print("Http Error")
        except json.JSONDecodeError:
            print("Json illegal")
        

if __name__ == "__main__":
    ecc1 = ECC_P256()
    http_sender = HttpHandler()
    server_pk_pem = ecc1.read_pk_pem()
    encrypted_message = ecc1.asymmetric_encryption(b"my name is walker",server_pk_pem)
    http_sender.send_encrypted_message(encrypted_message)