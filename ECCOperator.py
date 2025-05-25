import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

#lib source: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/

class ECC_P256:
    def __init__(self,dev_mode = False):
        self.dev_mode = dev_mode
        self.private_key = None
        self.public_key = None
        self.private_key_pem = None
        self.public_key_pem =None
        self.__read_keys()

    def __read_keys(self):
        try:
            with open("private_key.pem",'rb') as f:
                sk_pem = f.read()
                self.private_key = serialization.load_pem_private_key(sk_pem,password=None)
            with open("public_key.pem",'rb')as f:
                pk_pem = f.read()
                self.public_key = serialization.load_pem_public_key(pk_pem)
            self.private_key_pem,self.public_key_pem = self.__keys_serialization()
            print("Load keys successfully")
            if self.dev_mode == True:
                self.print_keys()
        except FileNotFoundError:
            print("No keys found!\t Creating....")
            self.__generate_keys()
        except Exception as e:
            print(f"Error {e} occur!")

    def __generate_keys(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        self.private_key_pem,self.public_key_pem = self.__keys_serialization()
        if self.dev_mode == True:
            self.print_keys()
        self.__store_keys()

    def __keys_serialization(self):
        serialization_private_key = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        serialization_public_key = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return serialization_private_key,serialization_public_key

    def __store_keys(self):#we use pem formate to store our keys info
        with open("private_key.pem","wb") as f:
            f.write(self.private_key_pem)
        with open("public_key.pem","wb") as f:
            f.write(self.public_key_pem)

    def print_keys(self):
        print(f"Private Key(pem):\n{self.private_key_pem}")
        print(f"Public Key:(pem)\n{self.public_key_pem}")

    def asymmetric_encryption(self,message,receiver_pk_pem):
        receiver_pk = serialization.load_pem_public_key(receiver_pk_pem)
        temp_key = ec.generate_private_key(ec.SECP256R1())
        share_key = temp_key.exchange(ec.ECDH(),receiver_pk)
        aes_key = HKDF(algorithm=hashes.SHA256(),length=32, salt=None, info=b"ecies").derive(share_key)
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        secert = aesgcm.encrypt(nonce,message,None)
        return {"temp_key":temp_key.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint),
                "nonce":nonce,"secret":secert}

    def asymmetric_decryption(self,secret_package):
        temp_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),secret_package['temp_key'])
        share_key = self.private_key.exchange(ec.ECDH(),temp_key)
        aes_key = HKDF(algorithm=hashes.SHA256(),length=32, salt=None, info=b"ecies").derive(share_key)
        return AESGCM(aes_key).decrypt(secret_package['nonce'],secret_package['secret'],None)
    
    def signature(self,message):
        return self.private_key.sign(message,ec.ECDSA(hashes.SHA256()))
    
    def verify_signature(self,message,sign):
        try:
            self.public_key.verify(sign,message,ec.ECDSA(hashes.SHA256()))
            return True
        except:
            return False

    def generate_session_key(self,receiver_pk_pem):
        share_key = self.private_key.exchange(ec.ECDH(),serialization.load_pem_public_key(receiver_pk_pem))
        session_key = HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b"handshake data").derive(share_key)
        return session_key
    
    def symmetric_encryption(self,message,session_key):
        aesgcm = AESGCM(session_key)
        nonce = os.urandom(12)
        secret = aesgcm.encrypt(nonce,message,None)
        return {"secret":secret,"nonce":nonce}

    def symmetric_decryption(self,secret_package,session_key):
        aesgcm = AESGCM(session_key)
        message = aesgcm.decrypt(secret_package['nonce'],secret_package['secret'],None)
        return message


if __name__ =="__main__":
    ECC_1 = ECC_P256(dev_mode=True)
    ECC_2 = ECC_P256(dev_mode=True)
    secret = ECC_2.asymmetric_encryption(b"HI",ECC_1.public_key_pem)
    print(ECC_1.asymmetric_decryption(secret))
