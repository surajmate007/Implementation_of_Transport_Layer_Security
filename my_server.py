import socket
from OpenSSL import crypto
import os
from datetime import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from matplotlib.pyplot import bar_label
import time


client_cert_path = ""
client_key_path = ""


server_cn = input("Enter username for which certificate to be genarated: ")
server_cert_path = "Server/{}.pem".format(server_cn)
server_key_path = "Server/public_key.pem"


# Creaing the new scket for communication between client and server

print("Creating new socket to connect to client")
serverSoc2 = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
serverSoc2.bind(("127.0.0.1", 5000))
serverSoc2.listen(5)

while True:
    print("Serve is waiting for connection")
    clientSoc2, addr2 = serverSoc2.accept()
    break


class Server_Client:                                                # main server to client class 

    def generateKey(self, key_path, key_exchange, encryption, hash):

        if(key_exchange == "ECDSA"):                                    # if the algorithm mentioned is ECDSA then generating the keys for ECDSA
            private_key_server = ec.generate_private_key(ec.SECP384R1())
            public_key_server = private_key_server.public_key()            # All are then methods from cryptography library.
            print("ECDSA key pair generated successfully")
            

        elif(key_exchange == "RSA"):                                    # if the algorithm is RSA then generating keys for RSA
            private_key_server = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key_server = private_key_server.public_key()
            print("RSA key pair generated successfully")

        if not os.path.exists('Server'):
            os.makedirs("Server")

        # storing both public and private keys of server

        with open("Server/private_key.pem", "wb") as f:
            f.write(private_key_server.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, 
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),))

        with open("Server/public_key.pem", "wb") as f:
            f.write(public_key_server.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))


        print("Keys generated successfully.")
        return private_key_server, public_key_server
            


    def getCertificate(self, server_key):                           # Using This method server will communicate with TTP to get the certificate
        csr=x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, input("Enter Country Code: ")),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, input("Enter state or provience: ")),                # providing all details for cetificate signing request
            x509.NameAttribute(NameOID.LOCALITY_NAME, input("Enter Locality Name: ")),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, input("Enter organisation name: ")),
            x509.NameAttribute(NameOID.COMMON_NAME, input("Enter domain name: ")),])).add_extension(x509.SubjectAlternativeName([x509.DNSName(u"mysite.com"),
            x509.DNSName(u"www.{}.com".format(input(server_cn))), 
            x509.DNSName(u"subdomain.mysite.com"),]),critical=False,).sign(server_key, hashes.SHA256())          # Sign the CSR with servers private key.

        with open("Server/csr.pem", "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))           # storig the CSR in Server directory.
        
        # creating certificate signing request and sending it to TTP

        signing_req_path = "Server/csr.pem"
        payload = "CERTIFICATE SIGNING REQUEST AT {} AND PUBLIC KEY AT Server/public_key.pem FOR USERNAME {} \n".format(signing_req_path, server_cn)
        CA_cert_path = ""                                   

        while True:
            try:
                # sending the signing request to TTP

                serverSoc1.send(payload.encode("utf-8"))
                print("Certificate signing request sent successfully")
        
                data = serverSoc1.recv(1024)
                data = data.decode("utf-8")
                data = data.split(" ")
                if(data[0] == "SUCCESSFUL"):
                    print("Certificate created successfully.")
                    
                print(data)
                CA_cert_path = data[1]
                print(CA_cert_path)

            except:
                print("TTP unavailable. Try again Later")

            break

        serverSoc1.close()                                                  
        return CA_cert_path


    def verifyCertificates(self, CA_cert_path):                   # This method is used to verify client and TTP certificate

        with open(server_cert_path, "r") as f:
            client_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

        with open(server_key_path, "r") as f:
            client_key = crypto.load_publickey(crypto.FILETYPE_PEM, f.read())               # loading all required cetificates
        
        with open(CA_cert_path, "r") as f:
            CA_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
        
        print("All certificates are loaded...")

        ca_expiry = datetime.strptime(str(CA_cert.get_notAfter(), 'utf-8'),"%Y%m%d%H%M%SZ")
        now = datetime.now()
        validity = (ca_expiry - now).days

        print ("CA Certificate valid for {} days".format(validity))

        print("CA certificate is successfully Verified.")

        client_expiry = datetime.strptime(str(client_cert.get_notAfter(), 'utf-8'),"%Y%m%d%H%M%SZ")         # checking expiery of these certificates
        now = datetime.now()
        validity = (client_expiry - now).days
        print ("Client Certificate valid for {} days".format(validity))
        
        client_pubkey = client_cert.get_pubkey()
        print("Client certificate is successfully Verified.")



    def ciphersuite(self):                                      # This method is used to exchange ciphersuite between clint and server
        while True:
            print("Server is waiting for ciphersuite")
            data = clientSoc2.recv(1024)
            if not data or data.decode("utf-8")=="END":
                break
            data = data.decode("utf-8")
            print("message received is: ", data)
            data = data.split("\n")
            a = data[0]     
            b = data[1]
            c = data[2]
            
            key_exchange = input(a + " :-----> ")           # Taking user input for the ciphersuite to use
            encryption = input(b + " :-----> ")
            hash = input(c + " :-----> ")

            ack = "{} {} {}".format(key_exchange, encryption, hash)             # creating the ack message to send oit back to server.
            while True:
                clientSoc2.send(ack.encode("utf-8"))
                print("Ciphersuite ACK sent successfully.")
                break

            private_key_server, public_key_server = self.generateKey(server_key_path, key_exchange, encryption, hash)       # calling the generate key finction to create the required keys.
            break
        
        print("client and server finalised the ciphersuite.")
        return key_exchange, encryption, hash, private_key_server, public_key_server


    def communicateKey(self, key_exchange):                 # This method is used to communicate the keys between client and server
        symmetric_key = None
        while True:
            ciphertext = clientSoc2.recv(1024)
            print("ciphertext is: ", ciphertext)

            if(key_exchange == "RSA"):                      # if key exchange is RSA then using RSA encryption on the key.
                print("Entered for decryption.")
                symmetric_key = private_key_server.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

                print("Key decrypted successfully.")
                suc = "SUCCESSFUL"
                while True:
                    try:
                        clientSoc2.send(suc.encode("utf-8"))        # sending the ack that the ciphertext is received.
                        print("ack sent successfully.")
                    except:
                        print("Cleint unavailable ")
                    break

            elif(key_exchange == 'ECDSA'):                  # using ECDSA for key exchange 
                data = ciphertext.split(" ")
                symmetric_key = data[0]
                signature = data[1]
                try:
                    public_key_server.verify(signature, bytes(str(symmetric_key), "utf-8"), ec.ECDSA(hashes.SHA256()))
                    print("Signature verified successfully")
                    suc = "SUCCESSFUL"
                    clientSoc2.send(suc.encode("utf-8"))
                except:
                    print("Error Occured in signature verification")
                
                print("Client unreachable...")
            
            break
        return symmetric_key


    def sendOTP(self, symmetric_key, encryption):                       # the method is used to exchange OTP between server and client
        OTP = b'''The OTP for transferring Rs 1,00,000 to your friend's account is 256345.'''
        nonce = os.urandom(16)                  # generating the nonce value to encrypt the message
        while True:
            try:
                clientSoc2.send(nonce)            
                print("Nonce sent successfully")

            except:
                print("Client unreachable.")
            break

        if(encryption == "AES"):                # if encryption os AES then using this to send the encrypted message
            print("Encrypting using AES")
            plaintext = pad(OTP, AES.block_size)
            print("The padded plaintext is : ", plaintext)
            cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(nonce))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            print("CIPHERTEXT SUCCESSFULLY GENERATED: ", ciphertext)

        elif(encryption == "CHACHA20"):         # if encryption os CHACHA20 then using this to send the encrypted message 
            print("Encrypting using CHACHA20")
            algorithm = algorithms.ChaCha20(symmetric_key, nonce)
            cipher = Cipher(algorithm, mode=None)
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(OTP)
            print("CIPHERTEXT SUCCESSFULLY GENERATED: ", ciphertext)


        while True:
            try:
                clientSoc2.send(ciphertext)                 # Sending the encrypted message to client
                print("ciphertext sent successfully.")

                while True:
                    try:
                        data = clientSoc2.recv(1024)                # Receiving the acknowledgment from client 
                        data = data.decode("utf-8")
                        print(data)
                        if(data == "SUCCESSFUL"):                   # checking whether the transfer was successful or not
                            print("OTP sent and decrypted successfully.")
                    except Exception as e:
                        print("Exception is: ", e)
                    break

            except:
                print("Client unavailbale in OTP")

            break



sc = Server_Client()
key_exchange, encryption, hash, private_key_server, public_key_server = sc.ciphersuite()            # calling the ciphersuite function


serverSoc1 = socket.socket(family=socket.AF_INET, type = socket.SOCK_STREAM)
serverSoc1.connect(("127.0.0.1", 15000))


CA_cert_path = sc.getCertificate(private_key_server)                # calling the get certificate function to get TTP signed certificates

serverSoc1.close()


while True:
    try:
        print("server waiting for connection")                      

        data = clientSoc2.recv(1024)
        if not data or data.decode("utf-8")=="END":
            break
        req = data.decode("utf-8")
        req = req.split(" ")

        if(req[0]=="VERIFY" and req[1] == "CLIENT" and req[2]=="CERTIFICATE" and req[3]=="AND" and req[4]=="KEY"):      # checking the verification request is well formed or not
            print("Certification verification request successfully received.")
            client_cert_path = req[7] 
            client_key_path = req[9]
            print(client_cert_path)
            print(client_key_path)
            print("going to verify certificates")
            sc.verifyCertificates(CA_cert_path)                         # calling the verify certificates function

        else:
            nack = "VALUE ERROR, TRY AGAIN"
            clientSoc2.send(bytes(nack, "utf-8"))
        
        print("server paths: ")
        print(server_cert_path)
        print(server_key_path)

        vrfReq = "VERIFY SERVER CERTIFICATE AND KEY AT PATH {} AND {}".format(server_cert_path, server_key_path)        # creating own request for certificate verification

        while True:
            try:
                clientSoc2.send(vrfReq.encode("utf-8"))             # sending request to client
                print("Certificate verification message sent succesfully")
                
            except:
                print("Client unreachable 1")

            break

    except Exception as e:
        print("Client unreachable 2")
        print("The reason is: ", e)

    break



while True:
    try:
        data = clientSoc2.recv(1024)
        data = data.decode("utf-8")
        print(data)
        if(data == "READY"):                # waiting for client to be ready 
            pass
    except:
        print("...")

    break

symmetric_key = sc.communicateKey(key_exchange)                     # calling the function to communicate the symmetric key
print("The symmetric key for coommunication is: ", symmetric_key)

while True:
    try:
        data = clientSoc2.recv(1024)
        data = data.decode("utf-8")
        print(data)
        if(data == "READY"):                # waiting for client to be ready 
            pass
    except:
        print("...")

    break

sc.sendOTP(symmetric_key, encryption)                               # calling the function to communicate the OTP message from server to client 

serverSoc2.close()                   # closing the socket between client and server