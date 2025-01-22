from pydoc import plain
import socket
from OpenSSL import crypto
import os
from datetime import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes



server_cert_path = ""
server_key_path = ""


client_cn = input("Enter username for which certificate to be genarated: ")
client_key_path = "Client/public.key"
client_cert_path = "Client/{}.crt".format(client_cn)

server_cert = None
server_key = None
CA_cert = None
CA_key = None

# socket created for communication between client and server

print("connecting to the new socket created by server")
clientSoc2 = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
clientSoc2.connect(("127.0.0.1", 5000))


class Client_Server:

    def generateKey(self, key_path, key_exchange, encryption, hash):            # function to generate the keys for the algothms of choice
        if(key_exchange == "ECDSA"):
            private_key_client = ec.generate_private_key(ec.SECP384R1())
            public_key_client = private_key_client.public_key()
            print("ECDSA Key pair successfully generated.")

        elif(key_exchange == "RSA"):
            private_key_client = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key_client = private_key_client.public_key()
            print("RSA Key pair successfully generated.")

        if(encryption == "AES"):                                    # AES key for symmetric algorithms
            symmetric_key = os.urandom(16)
            print("AES symmetric Key successfully generated.")

        elif(encryption == "CHACHA20"):                             # CHACHA20 key for symmetric algorithm
            symmetric_key = os.urandom(32)
            print("CHACHA20 symmetric Key successfully generated.")


        if not os.path.exists('Client'):                
            os.makedirs("Client")

        # storing the keys in the directory

        with open("Client/private_key.pem", "wb") as f:
                f.write(private_key_client.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, 
                encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),))
        
        with open("Client/public_key.pem", "wb") as f:
            f.write(public_key_client.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))

        return private_key_client, public_key_client, symmetric_key

        
    def getCertificate(self, client_key):
        csr=x509.CertificateSigningRequestBuilder().subject_name(x509.Name([                # creating certificate signing request
            x509.NameAttribute(NameOID.COUNTRY_NAME, input("Enter Country Code: ")),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, input("Enter state or provience: ")),
            x509.NameAttribute(NameOID.LOCALITY_NAME, input("Enter Locality Name: ")),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, input("Enter organisation name: ")),
            x509.NameAttribute(NameOID.COMMON_NAME, input("Enter domain name: ")),])).add_extension(x509.SubjectAlternativeName([x509.DNSName(u"mysite.com"),
            x509.DNSName(u"www.{}.com".format(input(client_cn))), 
            x509.DNSName(u"subdomain.mysite.com"),]),critical=False,).sign(client_key, hashes.SHA256())         # Sign the CSR with our private key.

        with open("Client/csr.pem", "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))                           # soring the csr file
        
        signing_req_path = "Client/csr.pem"
        payload = "CERTIFICATE SIGNING REQUEST AT {} AND PUBLIC KEY AT Client/public_key.pem FOR USERNAME {}".format(signing_req_path, client_cn)
        CA_cert_path = ""

        while True:
            try:
                clientSoc1.send(payload.encode("utf-8"))
                print("Certificate signing request sent successfully")

                data = clientSoc1.recv(1024)
                data = data.decode("utf-8")
                data = data.split(" ")
                if(data[0] == "SUCCESSFUL"):
                    print("Certificate created successfully.")
                CA_cert_path = data[1]
                print(CA_cert_path)
                
            except:
                print("TTP unavailable. Try again Later")
            break

        clientSoc1.close()
        return CA_cert_path
        

    def verifyCertificates(self, CA_cert_path):                                               # creating and sending certificate verification request
        
        # loading all the certificates for verification

        with open(server_cert_path, "r") as f:
            server_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

        with open(server_key_path, "r") as f:
            server_key = crypto.load_publickey(crypto.FILETYPE_PEM, f.read())
        
        with open(CA_cert_path, "r") as f:
            CA_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
        
        ca_expiry = datetime.strptime(str(CA_cert.get_notAfter(), 'utf-8'),"%Y%m%d%H%M%SZ")         # checing the validity of certificate
        now = datetime.now()
        validity = (ca_expiry - now).days
        print ("CA Certificate valid for {} days".format(validity))

        CA_pubkey = CA_cert.get_pubkey()
        if(CA_pubkey == CA_key):
            print("CA Certificate is successfully Verified.")
        
        server_expiry = datetime.strptime(str(server_cert.get_notAfter(), 'utf-8'),"%Y%m%d%H%M%SZ")
        now = datetime.now()
        validity = (server_expiry - now).days
        print ("Server Certificate valid for {} days".format(validity))

        server_pubkey = server_cert.get_pubkey()
        print("Server certificate successfully Verified.")


    def cipherSuite(self):                                      # exchanging ciphersuite between client and server
        payload = "WHICH KEY EXCHANGE TO USE ECDSA, RSA \n WHICH SYMMETRIC ENCRYPTON TO USE AES, CHACHA20 \n WHICH HASH TO USE SHA256, SHA384"
        clientSoc2.send(payload.encode("utf-8"))
        print("Ciphersuite sent successfully.")

        while True:
            data = clientSoc2.recv(1024)                        # receiving the acknowledgment from the server
            data = data.decode("utf-8")
            print("The received ACK is: ", data)
            data = data.split(" ")
            key_exchange = data[0]
            encryption = data[1]
            hash = data[2]
            private_key_client, public_key_client, symmetric_key = self.generateKey(client_key_path, key_exchange, encryption, hash)        # calling the generate key function
            break
        print("Client and Server finalised the ciphersuite.")

        return key_exchange, encryption, hash, private_key_client, public_key_client, symmetric_key


    def communicateKey(self, symmetric_key, key_exchange):      # Symmetric key is communicated between client and server.
        public_key_server = None

        with open(server_key_path, "rb") as f:
            public_key_server = serialization.load_pem_public_key(f.read())


        if(key_exchange == "RSA"):                  # if key exchange algo is RSA then using it for key encryption
            ciphertext = public_key_server.encrypt(symmetric_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            while True:
                try:
                    clientSoc2.send(ciphertext)
                    print("Encrypted key sent")
                    data = clientSoc2.recv(1024)

                    print("The ciphertext is: ", ciphertext)

                    print("The data is : ", data)

                    print("Key reached succcessfully.")

                except Exception as e:
                    print("server unavailable !")
                    print("The exception is : ", e)

                break

        elif(key_exchange == "ECDSA"):              # if key exchange algo is ECDSA then using it for key encryption
            private_key = ec.generate_private_key(ec.SECP384R1())
            data = bytes(str(symmetric_key), "utf-8")
            signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
            while True:
                try:
                    clientSoc2.send("{} {}".format(symmetric_key, signature))
                    print("Encrypted key sent successfully.")
                    data = clientSoc2.recv(1024)
                    data = data.decode("utf-8")
                    if(data == "SUCCESSFUL"):
                        print("Key reached succcessfully.")
                except:
                    print("server unavailable !")
                break
    


    def recevOTP(self, symmetric_key, encryption):      # This funnction is called to receive the OTP message from server
        nonce = None
        ciphertext = None

        while True:
            try:
                nonce = clientSoc2.recv(1024)           # getting the nonce value from server to decrypt the messages
                print(nonce)
                print("Nonce received successfully: ", nonce)         
            except:
                print("Server unavalable in nonce 1.")
            break
            
        while True:
            print("Waiting for ciphertext...")
            try:
                ciphertext = clientSoc2.recv(1024)      # getting the ciphertext from server
                print("Ciphertext received is : ",ciphertext)
                ack = "SUCCESSFUL"
                clientSoc2.send(ack.encode("utf-8"))
            except:
                print("Server unavailable in nonce 2")
            
            break
        
        print("Decrypting the ciphertext...")

        if(encryption == "AES"):                        # if encryption algo is AES then decrypting using AES
            print("decrypting using AES.")

            print("Length of nonce is: ", len(nonce))

            cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(nonce))
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
        elif(encryption == "CHACHA20"):                 # encryption algo is CHACHA20 then decryption using CHACHA20
            print("decrypting using CHACHA20.")
            algorithm = algorithms.ChaCha20(symmetric_key, nonce)
            cipher = Cipher(algorithm, mode=None)
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext)

        print("ciphertext decrypted successfully.")
        print("Plaintext is: ", plaintext)
        plaintext = plaintext.decode("utf-8")
        return plaintext                                # returning the plaintext
            



cs = Client_Server()
key_exchnage, encryption, hash, private_key_client, public_key_client, symmetric_key = cs.cipherSuite()

# Creating socket to communicate with TTP

clientSoc1= socket.socket(family=socket.AF_INET, type = socket.SOCK_STREAM)         
clientSoc1.connect(("127.0.0.1", 16000))

CA_cert_path = cs.getCertificate(private_key_client)            # calling get cetificate method

clientSoc1.close()


vrfReq = "VERIFY CLIENT CERTIFICATE AND KEY AT PATH {} AND {}".format(client_cert_path, client_key_path)
while True:
    try:
        clientSoc2.send(vrfReq.encode("utf-8"))
        print("Certificate verification message sent successfully")

        while True:
            try:
                data = clientSoc2.recv(1024)
                if not data or data.decode("utf-8")=="END":
                    break
                req = data.decode("utf-8")
                print("The req is: ", req)
                req = req.split(" ")
                if(req[0]=="VERIFY" and req[1] == "SERVER" and req[2]=="CERTIFICATE" and req[3]=="AND" and req[4]=="KEY"):
                    print("Certification verification request successfully received.")
                    server_cert_path = req[7] 
                    server_key_path = req[9]

                    cs.verifyCertificates(CA_cert_path)                     # calling verif certificate method

                else:
                    nack = "VALUE ERROR, TRY AGAIN"
                    clientSoc2.send(bytes(nack, "utf-8"))
                    
            except:
                print("Server unreachable.")
            break
        
    except:
        print("Server unreachable...")
    break



while True:
    try:
        clientSoc2.send("READY".encode("utf-8"))
        print("Ready sent successfully.")
    except:
        print("...")

    break

cs.communicateKey(symmetric_key, key_exchnage)  # calling this function to get the keys 


while True:
    try:
        clientSoc2.send("READY".encode("utf-8"))
        print("Ready sent successfully.")
    except:
        print("...")

    break

OTP = cs.recevOTP(symmetric_key, encryption)    # calling the receive OTP function
print("\n")
print(OTP)                                      # printing the plaintext


clientSoc2.close()                              # closing the socket between client and server 