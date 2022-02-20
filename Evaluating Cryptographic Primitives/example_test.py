from execute_crypto import ExecuteCrypto
import time

f = open("/source/submissions/original_plaintext.txt","r")
lines = f.readlines()
plainText  = "".join(lines)

cipherTextcbc = a.encrypt('AES-128-CBC-ENC', symmetric_key, plainText, nonce_aes_cbc)
plainTextcbc = a.decrypt('AES-128-CBC-DEC', symmetric_key, cipherTextcbc, nonce_aes_cbc)

cipherTextctr = a.encrypt('AES-128-CTR-ENC', symmetric_key, plainText, nonce_aes_ctr)
plainTextctr = a.decrypt('AES-128-CTR-DEC', symmetric_key, cipherTextctr, nonce_aes_ctr)

cipherTextRSA = a.encrypt('RSA-2048-ENC', public_key_sender_rsa, symmetric_key, nonce_tag_rsa)
plainTextRSA = a.decrypt('RSA-2048-DEC', private_key_sender_rsa, cipherTextRSA, nonce_tag_rsa)

auth_tag_cmac = a.generate_auth_tag('AES-128-CMAC-GEN', symmetric_key, plainText, nonce_aes_cbc)
auth_tag_cmac_valid = a.verify_auth_tag('AES-128-CMAC-VRF', symmetric_key, plainTextcbc[0:len(plainText)], nonce_aes_cbc, auth_tag_cmac)

auth_tag_hmac = a.generate_auth_tag('SHA3-256-HMAC-GEN', symmetric_key, plainText, nonce_aes_cbc)
auth_tag_hmac_valid = a.verify_auth_tag('SHA3-256-HMAC-VRF', symmetric_key, plainTextcbc[0:len(plainText)], nonce_aes_cbc, auth_tag_hmac)

auth_tag_RSA = a.generate_auth_tag('RSA-2048-SHA3-256-SIG-GEN', private_key_sender_rsa, symmetric_key, nonce_tag_rsa)
auth_tag_RSA_valid = a.verify_auth_tag('RSA-2048-SHA3-256-SIG-VRF', public_key_sender_rsa, plainTextRSA, nonce_tag_rsa, auth_tag_RSA)

auth_tag_ecd = a.generate_auth_tag('ECDSA-256-SHA3-256-SIG-GEN', private_key_sender_ecc, plainText, nonce_ecdsa)
auth_tag_ecd_valid = a.verify_auth_tag('ECDSA-256-SHA3-256-SIG-VRF', public_key_sender_ecc, plainText, nonce_ecdsa, auth_tag_ecd)

cipherTextEnc, auth_tagEnc = a.encrypt_generate_auth('AES-128-GCM-GEN', symmetric_key, auth_tag_cmac, plainText, nonce_aes_gcm)
plainTextDec, auth_tagDec = a.decrypt_verify_auth('AES-128-GCM-VRF', symmetric_key, symmetric_key, cipherTextEnc, nonce_aes_gcm, auth_tagEnc)
