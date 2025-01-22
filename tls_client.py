#!/usr/bin/python3

import socket, ssl, sys, pprint

hostname = sys.argv[1]
port = 443
cadir = 'etc/ssl/certs'

# Set up the TLS context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_verify_locations(capath=cadir)
context.verify_mode = ssl.CERT_REQUIRED

context.check_hostname = False
# Create TCP connection
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((hostname, port))
input("After making TCP connection. Press any key to continue ...")
# Add the TLS
ssock = context.wrap_socket(sock, server_hostname=hostname, do_handshake_on_connect=False)
ssock.do_handshake() # Start the SSL setup handshake.

serverCert = ssock.getpeercert()
print("The server certificate is as follows: ")
pprint.pprint(serverCert)

input("After handshake. Press any key to continue ...")


# matching the certificate. When the histname is correctly matched then no error is raised while if the hstname is not matched then error is raised.
# ssl.match_hostname(serverCert, "www.google.com")

# to get the cipher getting used in this TLS connection we use the following command "socket_name.cpher()".
# it returns a tuple of three entries ie. name of cipher used, version of cipher used and size of thekey getting used.

(name, version, size) = ssock.cipher();
print("The name of cipher is: ", name)
print("The version of cipher is: ", version)
print("The size of key getting used in cipher is: {} bytes".format(size))

# Send HTTP Request to Server

print("Sending HTTP request to server.")

# We can change the below hostname and replace it with some hostname of image. Hence the program will fetch the required image.

request = b"GET / HTTP/1.0\r\nHost: " + \
    hostname.encode("utf-8") + b"\r\n\r\n"


ssock.sendall(request)
# Read HTTP Response from Server
response = ssock.recv(2048)

while response:
    pprint.pprint(response.split(b"\r\n"))
    response = ssock.recv(2048)

# Close the TLS Connection
ssock.close()