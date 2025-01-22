import socket
from OpenSSL import crypto
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

# paths for CS certificate and CA key

CA_cert_path = "CA/cert.pem"
CA_key_path = "CA/key.pem"

csr_path_client = ""
csr_path_server = ""

# This is main class which contains all the functions required to implement the TTP side

class Trusted_Third_Party:
    
    def create_CA_Certificate(self):                                                # This method will help to create the certificate for CA
        
        CA_key = rsa.generate_private_key(public_exponent=65537, key_size=2048,)    # We will generate key pair for TTP and the store it in CA directory
        if not os.path.exists('CA'):
            os.makedirs('CA')

        with open(CA_key_path, "wb") as f:                                          # storing the keys in CS directory
            f.write(CA_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, 
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),))

        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, input("Enter country code: ")),      # Providing all the details for certificate creation
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, input("Enter state or province name: ")),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, input("Enter locality name: ")),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Enter Organisation Name: "),
                    x509.NameAttribute(NameOID.COMMON_NAME, input("Enter website domain name: ")),])

        # Creating the certificate by feeding in the details.
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(CA_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10)).add_extension(x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),critical=False,).sign(CA_key, hashes.SHA256())

        with open(CA_cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))      # Storing the CA ertificate in the CA directory
            
        return CA_key



    def create_Client_Certificate(self, CA_key, client_cn, sock, prefix):           # This method is used to create the client certificate

        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),  # Keeping default detail for client and server
                    x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
                    x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),])

        # Generating the certificate
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(CA_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10)).add_extension(x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),critical=False,).sign(CA_key, hashes.SHA256())

        with open("{}/{}.pem".format(prefix, client_cn), "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))                  # storing the certificate
        
        while True:
            try:
                payload = "SUCCESSFUL {}".format(CA_cert_path)
                sock.send(payload.encode("utf-8"))                                  # sending acknowledgment message to client and server

            except:
                print("Server Unavailable...")

            break
        return


ttp = Trusted_Third_Party()                                                         # creating class object
CA_key = ttp.create_CA_Certificate()

ttpSoc2 = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)  # creating socket for client
ttpSoc2.bind(("127.0.0.1", 16000))
ttpSoc2.listen(5)

ttpSoc1 = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)  # creating socket for server
ttpSoc1.bind(("127.0.0.1", 15000))
ttpSoc1.listen(5)


while True:

    print("TTP waiting for client to connect")
    clientSoc2, addr2 = ttpSoc2.accept()

    while True:
        data = clientSoc2.recv(1024)
        if not data or data.decode("utf-8")=="END":
            break
        req = data.decode("utf-8")
        req = req.split(" ")
        if(req[0]=="CERTIFICATE" and req[1]=="SIGNING" and req[2]=="REQUEST" and req[3]=="AT"):         # checking whether the signing request is on correct format or not.
            print("Certification request successfully received from client.")
            csr_path_client = req[4]
            public_key_path_client = req[9]
            username = req[12]

        else:
            nack = "VALUE ERROR, TRY AGAIN"                             # If not in correcct format then returning value error.
            clientSoc2.send(bytes(nack, "utf-8"))

        ttp.create_Client_Certificate(CA_key, username, clientSoc2, prefix = "Client")      # calling for creating certifiate
        print("Client certificate created successfully.")

        break

    break

ttpSoc2.close()



while True:

    print("TTP waiting for server to connect")
    clientSoc1, addr1 = ttpSoc1.accept()

    while True:
        data = clientSoc1.recv(1024)
        if not data or data.decode("utf-8")=="END":
            break
        req = data.decode("utf-8")
        req = req.split(" ")
        if(req[0]=="CERTIFICATE" and req[1]=="SIGNING" and req[2]=="REQUEST" and req[3]=="AT"):         # checking whether the signing request is on correct format or not.
            print("Certification request successfully received for server.")
            csr_path_server = req[4]
            public_key_path_server = req[9]
            username = req[12]

        else:
            nack = "VALUE ERROR, TRY AGAIN"                                                             # if not in correct format then returning value error        
            clientSoc1.send(bytes(nack, "utf-8"))
            break

        ttp.create_Client_Certificate(CA_key, username, clientSoc1, prefix = "Server")                  # calling for creating certifiate
        print("Server certificate created successfully.")

        break

    break

ttpSoc1.close()