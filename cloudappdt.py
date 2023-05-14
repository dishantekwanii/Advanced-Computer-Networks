import dropbox
import os

# Enter Dropbox API key
DROPBOX_API_KEY = 'sl.BcoUsmUE3cIPCMgBdvBL8w8EXmvse6I1mI80kExlRsIgUJCubPvBH4ZEkNbH9GbVDLRxBgP-CozyONgH3kb57qzYl9mGPeyFob_jqvFu539tQr0pMyYAUhoGvn_q3jRBwGGcYlCpfRiN'

# Authenticate with Dropbox API
dbx = dropbox.Dropbox(DROPBOX_API_KEY)

# Define group name
GROUP_NAME = 'cloudgroupdt'

# Define key management system
class KeyManagementSystem:
    def __init__(self):
        self.public_key = None
        self.private_key = None
        self.users = []

    def generate_key_pair(self):
        # Generate public and private key pair using a cryptographic library
        self.public_key, self.private_key = generate_key_pair()

    def get_public_key(self):
        return self.public_key

    def add_user(self, user_public_key):
    	  self.users.append(user_public_key)
    	  dbx.sharing_add_file_member('/' + GROUP_NAME, [dropbox.sharing.MemberSelector.email(user_public_key)])
    	  print(f'Added user {user_public_key} to group {GROUP_NAME}')


    def remove_user(self, user_public_key):
        # Remove user from the group by revoking their access to the group key
        dbx.sharing_revoke_file_member('/' + GROUP_NAME, dropbox.sharing.MemberSelector.email(user_public_key))

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

# Generate a new RSA key pair
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key_bytes, public_key_bytes

# Encrypt a message using a public key
def encrypt(public_key, message):
    public_key = serialization.load_pem_public_key(
        public_key,
        backend=default_backend()
    )
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode()

# Decrypt a ciphertext using a private key
def decrypt(private_key, ciphertext):
    private_key = serialization.load_pem_private_key(
        private_key,
        password=None,
        backend=default_backend()
    )
    ciphertext = base64.b64decode(ciphertext.encode())
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()



# Define encryption and decryption functions
def encrypt_file(file_path, public_key):
    # Encrypt file using the user's public key
    encrypted_file = encrypt(file_path, public_key)
    # Upload encrypted file to Dropbox
    with open(file_path, 'rb') as f:
        dbx.files_upload(encrypted_file, '/' + os.path.basename(file_path))

def decrypt_file(file_path, private_key):
    # Download encrypted file from Dropbox
    _, encrypted_file = dbx.files_download('/' + os.path.basename(file_path))
    # Decrypt file using the user's private key
    decrypted_file = decrypt(encrypted_file, private_key)
    # Save decrypted file to local storage
    with open(file_path, 'wb') as f:
        f.write(decrypted_file)

# Example usage
# Generate key pair for the user
kms = KeyManagementSystem()
kms.generate_key_pair()
public_key = kms.get_public_key()

# Add user to the group
kms.add_user('tekwanid@tcd.ie')

# Upload file to Dropbox (encrypted with user's public key)
encrypt_file('/path/to/file', public_key)

# Download file from Dropbox (decrypted with user's private key)
decrypt_file('/path/to/file', kms.private_key)
