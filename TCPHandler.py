import socket
import time

STM32_IP_addr = "192.168.0.20"
STM32_port = 5000

class TCPHandler:
    def __init__(self,ip_addr= STM32_IP_addr,port = STM32_port):
        self.socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.socket.settimeout(5.0)
        self.connect_transmiter(ip_addr,port)
        
    def connect_transmiter(self,ip_addr,port):
        try:
            self.socket.connect((ip_addr,port))
        except Exception as e:
            print(f"Error while connecting to transmiter {e}")

    def get_temperature(self):
        try:
            self.socket.sendall(b"GET_TEMP\r\n")
            temp = self.socket.recv(64)
            return temp.decode("utf-8", errors="ignore").strip()
        except Exception as e:
            print(f"Error occur while get temperature{e}\n wait 5 sec")
            time.sleep(5)

if __name__ == "__main__":
    tcphandler = TCPHandler()
    while True:
        print(f"[{time.strftime('%H:%M:%S')}] 溫度：{tcphandler.get_temperature()}")
        time.sleep(2)