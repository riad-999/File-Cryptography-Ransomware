import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def decrypt_key(encrypted_key, private_key):

    # Import the Private Key and use for decryption using PKCS1_OAEP
    rsakey = RSA.importKey(private_key)
    rsakey = PKCS1_OAEP.new(rsakey)

    # Base 64 decode the data
    # encrypted_key = base64.b64decode(encrypted_key)

    # In determining the chunk size, determine the private key length used in bytes.
    # The data will be in decrypted in chunks
    chunk_size = 512
    offset = 0
    decrypted = b""

    # keep loop going as long as we have chunks to decrypt
    while offset < len(encrypted_key):
        # The chunk
        chunk = encrypted_key[offset: offset + chunk_size]

        # Append the decrypted chunk to the overall decrypted file
        decrypted += rsakey.decrypt(chunk)

        # Increase the offset by chunk size
        offset += chunk_size

    return decrypted.strip()

# create a socket object
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# get local machine name
host = '127.0.0.1'
port = 9999

# bind the socket to a public host, and a port
server_socket.bind((host, port))

# become a server socket
server_socket.listen(5)

while True:
    # establish a connection
    client_socket, addr = server_socket.accept()

    print("Got a connection from %s" % str(addr))

    # receive the client's request
    request = client_socket.recv(64)
    print(request.decode())

    with open("ids.txt", "r") as f:
        ids = f.readlines()

    id_exists = False
    for id in ids:
        if id.strip() == request.decode():
            id_exists = True
            break

    if id_exists:
        # if the id exists, send the file
        with open("private_key.pem", "rb") as f:
            private_key = f.read()
        key = client_socket.recv(5000)
        key = decrypt_key(key, private_key)
        client_socket.sendall(key)
    else:
        client_socket.sendall(b"unauthorized")

    # close the client connection
    client_socket.close()
