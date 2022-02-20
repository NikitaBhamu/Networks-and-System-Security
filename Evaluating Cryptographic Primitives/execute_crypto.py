# Write your script here
import Crypto
import rsa
from Crypto.PublicKey import RSA
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA3_256
from Crypto.Signature import DSS
from Crypto.Hash import CMAC, HMAC
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
import Crypto.Random
from pycoin import ecdsa
from sys import getsizeof
import random
import hashlib
import binascii
import base64
import string
import os
from timeit import default_timer as timer

class ExecuteCrypto(object): # Do not change this
    def generate_keys(self):
        """Generate keys"""

        # Write your script here

        symmetric_key = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        private_key_sender_rsa = RSA.generate(2048)
        public_key_sender_rsa = private_key_sender_rsa.public_key()
        private_key_receiver_rsa = RSA.generate(2048)
        public_key_receiver_rsa = private_key_receiver_rsa.public_key()
        public_key_sender_ecc = private_key_sender_rsa.public_key()
        private_key_sender_ecc = ECC.generate(curve='P-256')
        public_key_sender_ecc = private_key_sender_ecc.public_key()

        print("Symmetric Key") # Do not change this
        print(symmetric_key) # Do not change this
        print("Sender's RSA Public Key") # Do not change this
        print(public_key_sender_rsa) # Do not change this
        print("Sender's RSA Private Key") # Do not change this
        print(private_key_sender_rsa) # Do not change this
        print("Receiver's RSA Public Key") # Do not change this
        print(public_key_receiver_rsa) # Do not change this
        print("Receiver's RSA Private Key") # Do not change this
        print(private_key_receiver_rsa) # Do not change this
        print("Sender's ECC Public Key") # Do not change this
        print(public_key_sender_ecc) # Do not change this
        print("Sender's ECC Private Key") # Do not change this
        print(private_key_sender_ecc) # Do not change this

        return symmetric_key, \
                public_key_sender_rsa, private_key_sender_rsa, \
                public_key_receiver_rsa, private_key_receiver_rsa, \
                public_key_sender_ecc, private_key_sender_ecc # Do not change this

    def generate_nonces(self):
        """Generate nonces"""

        # Write your script here
        nonce_aes_cbc = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        nonce_aes_ctr = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        nonce_encrypt_rsa = ''
        nonce_aes_cmac = ''
        nonce_hmac = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        nonce_tag_rsa = ''
        nonce_ecdsa = ''
        nonce_aes_gcm = ''.join(random.choices(string.ascii_letters + string.digits, k=16))


        print("Nonce for AES-128-CBC") # Do not change this
        print(nonce_aes_cbc) # Do not change this
        print("Nonce for AES-128-CTR") # Do not change this
        print(nonce_aes_ctr) # Do not change this
        print("NOnce for RSA-2048") # Do not change this
        print(nonce_encrypt_rsa) # Do not change this
        print("Nonce for AES-128-CMAC") # Do not change this
        print(nonce_aes_cmac) # Do not change this
        print("Nonce for SHA3-256-HMAC") # Do not change this
        print(nonce_hmac) # Do not change this
        print("Nonce for RSA-2048-SHA3-256") # Do not change this
        print(nonce_tag_rsa) # Do not change this
        print("Nonce for ECDSA") # Do not change this
        print(nonce_ecdsa) # Do not change this
        print("Nonce for AES-128-GCM") # Do not change this
        print(nonce_aes_gcm) # Do not change this

        return nonce_aes_cbc, nonce_aes_ctr, nonce_encrypt_rsa, nonce_aes_cmac, \
                nonce_hmac, nonce_tag_rsa, nonce_ecdsa, nonce_aes_gcm # Do not change this

    def encrypt(self, algo, key, plaintext, nonce): # Do not change this
        """Encrypt the given plaintext"""

        # Write your script here

        if algo == 'AES-128-CBC-ENC': # Do not change this
            # Write your script here
            aes_cbc_cipher = AES.new(key.encode("UTF-8"), AES.MODE_CBC, iv=nonce.encode("UTF-8"))
            ciphertext = aes_cbc_cipher.encrypt(pad(plaintext.encode("UTF-8"), AES.block_size))

        elif algo == 'AES-128-CTR-ENC': # Do not change this
            # Write your script here
            aes_ctr_cipher = AES.new(key.encode("UTF-8"), AES.MODE_CTR, nonce=nonce.encode("UTF-8"))
            ciphertext = aes_ctr_cipher.encrypt(pad(plaintext.encode("UTF-8"), AES.block_size))

        elif algo == 'RSA-2048-ENC': # Do not change this
            # Write your script here
            rsa_cipher = PKCS1_OAEP.new(key)
            ciphertext = rsa_cipher.encrypt(plaintext.encode("UTF-8"))

        else: # Do not change this
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here


        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Encryption Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this

        return ciphertext # Do not change this

    def decrypt(self, algo, key, ciphertext, nonce): # Do not change this
        """Decrypt the given ciphertext"""
        # Write your script here

        if algo=='AES-128-CBC-DEC': # Do not change this
            # Write your script here
            aes_cbc_cipher = AES.new(key.encode("UTF-8"), AES.MODE_CBC, iv=nonce.encode("UTF-8"))
            padded_plaintext = aes_cbc_cipher.decrypt(ciphertext)
            plaintext = unpad(padded_plaintext, AES.block_size).decode()

        elif algo == 'AES-128-CTR-DEC': # Do not change this
            # Write your script here
            aes_ctr_cipher = AES.new(key.encode("UTF-8"), AES.MODE_CTR, nonce=nonce.encode("UTF-8"))
            padded_plaintext = aes_ctr_cipher.decrypt(ciphertext)
            plaintext = unpad(padded_plaintext, AES.block_size).decode()

        elif algo == 'RSA-2048-DEC': # Do not change this
            # Write your script here
            rsa_cipher = PKCS1_OAEP.new(key)
            plaintext = rsa_cipher.decrypt(ciphertext).decode()

        else: # Do not change this
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Decryption Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this
        return plaintext # Do not change this

    def generate_auth_tag(self, algo, key, plaintext, nonce): # Do not change this
        """Generate the authenticate tag for the given plaintext"""

        # Write your script here

        if algo =='AES-128-CMAC-GEN': # Do not change this
            # Write your script here
            cobj = CMAC.new(key.encode("UTF-8"), ciphermod=AES)
            cobj.update(plaintext.encode("UTF-8"))
            auth_tag = cobj.hexdigest()

        elif algo =='SHA3-256-HMAC-GEN': # Do not change this
            # Write your script here
            h = HMAC.new(key.encode("UTF-8"), digestmod=SHA3_256)
            h.update(plaintext.encode("UTF-8"))
            auth_tag = h.hexdigest()

        elif algo =='RSA-2048-SHA3-256-SIG-GEN': # Do not change this
            # Write your script here
            h = SHA3_256.new(plaintext.encode("UTF-8"))
            auth_tag = pkcs1_15.new(key).sign(h)

        elif algo =='ECDSA-256-SHA3-256-SIG-GEN': # Do not change this
            # Write your script here
            h = SHA3_256.new(plaintext.encode("UTF-8"))
            signer = DSS.new(key, 'fips-186-3')
            auth_tag = signer.sign(h)

        else:
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here


        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Authentication Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this

        return auth_tag # Do not change this

    def verify_auth_tag(self, algo, key, plaintext, nonce, auth_tag): # Do not change this
        """Verify the authenticate tag for the given plaintext"""

        # Write your script here

        if algo =='AES-128-CMAC-VRF': # Do not change this
            # Write your script here
            cobj = CMAC.new(key.encode("UTF-8"), ciphermod=AES)
            cobj.update(plaintext.encode("UTF-8"))
            try:
                cobj.hexverify(auth_tag)
                auth_tag_valid = True
            except ValueError:
                auth_tag_valid = False

        elif algo =='SHA3-256-HMAC-VRF': # Do not change this
            # Write your script here
             h = HMAC.new(key.encode("UTF-8"), digestmod=SHA3_256)
             h.update(plaintext.encode("UTF-8"))
             try:
                 h.hexverify(auth_tag)
                 auth_tag_valid = True
             except ValueError:
                 auth_tag_valid = False


        elif algo =='RSA-2048-SHA3-256-SIG-VRF': # Do not change this
            # Write your script here
             h = SHA3_256.new(plaintext.encode("UTF-8"))
             try:
                 pkcs1_15.new(key).verify(h, auth_tag)
                 auth_tag_valid = True
             except (ValueError, TypeError):
                 auth_tag_valid = False


        elif algo =='ECDSA-256-SHA3-256-SIG-VRF': # Do not change this
            # Write your script here
            h = SHA3_256.new(plaintext.encode("UTF-8"))
            verifier = DSS.new(key, 'fips-186-3')
            try:
                verifier.verify(h, auth_tag)
                auth_tag_valid = True
            except ValueError:
                auth_tag_valid = False


        else:
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Authentication Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this
        print("Authentication Tag Valid") # Do not change this
        print(auth_tag_valid) # Do not change this

        return auth_tag_valid # Do not change this


    def encrypt_generate_auth(self, algo, key_encrypt, key_generate_auth, plaintext, nonce): # Do not change this
        """Encrypt and generate the authentication tag for the given plaintext"""

        # Write your script here

        if algo == 'AES-128-GCM-GEN': # Do not change this
            # Write your script here
            cipher = AES.new(key_encrypt.encode("UTF-8"), AES.MODE_GCM, nonce=nonce.encode("UTF-8"))
            ciphertext, auth_tag = cipher.encrypt_and_digest(plaintext.encode("UTF-8"))

        else:
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Encryption Key") # Do not change this
        print(key_encrypt) # Do not change this
        print("Authentication Key") # Do not change this
        print(key_generate_auth) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this

        return ciphertext, auth_tag # Do not change this


    def decrypt_verify_auth(self, algo, key_decrypt, key_verify_auth, ciphertext, nonce, auth_tag): # Do not change this
        """Decrypt and verify the authentication tag for the given plaintext"""

        # Write your script here

        if algo == 'AES-128-GCM-VRF': # Do not change this
            # Write your script here
            try:
                cipher = AES.new(key_decrypt.encode("UTF-8"), AES.MODE_GCM, nonce=nonce.encode("UTF-8"))
                plaintext = cipher.decrypt_and_verify(ciphertext, auth_tag).decode()
                auth_tag_valid = True
            except (ValueError, KeyError):
                plaintext = None
                auth_tag_valid = False

        else:
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Decryption Key") # Do not change this
        print(key_decrypt) # Do not change this
        print("Authentication Key") # Do not change this
        print(key_verify_auth) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this
        print("Authentication Tag Valid") # Do not change this
        print(auth_tag_valid) # Do not change this

        return plaintext, auth_tag_valid # Do not change this



if __name__ == '__main__': # Do not change this
    ExecuteCrypto() # Do not change this
