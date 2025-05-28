import requests

function_list = {"send_encrypted_message":"decrypt"}

class HttpHandler:

    def __init__(self,server_url = "http://127.0.0.1:5000/"):
        self.server_url = str(server_url)
        
    def send_encrypted_message(self,encrypted_message):
        try:
            url = self.server_url+function["send_encrypted_message"]
            payload = 
        except
        