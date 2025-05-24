from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

#lib source: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/

class ECC_P256:
    def __init__(self,dev_mode = False):
        self.dev_mode = dev_mode
        self.private_key = None
        self.public_key = None
        self.read_keys()

    def read_keys(self):
        try:
            with open("private_key.pem",'rb') as f:
                sk_pem = f.read()
                self.private_key = serialization.load_pem_private_key(sk_pem,password=None)
            with open("public_key.pem",'rb')as f:
                pk_pem = f.read()
                self.public_key = serialization.load_pem_public_key(pk_pem)
            if self.dev_mode == True:
                self.print_keys()
        except FileNotFoundError:
            print("No keys found!\t Creating....")
            self.generate_keys()
        except Exception as e:
            print(f"Error {e} occur!")

    def generate_keys(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        if self.dev_mode == True:
            self.print_keys()
        sk_pem,pk_pem = self.keys_serialization()
        self.store_keys(sk_pem,pk_pem)

    def keys_serialization(self):
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

    def print_keys(self):
        sk,pk=self.keys_serialization()
        print(f"Private Key:\n{sk}")
        print(f"Public Key:\n{pk}")

    def store_keys(self,sk_pem,pk_pem):
        with open("private_key.pem","wb") as f:
            f.write(sk_pem)
        with open("public_key.pem","wb") as f:
            f.write(pk_pem)


if __name__ =="__main__":
    ECC = ECC_P256(dev_mode=True)
