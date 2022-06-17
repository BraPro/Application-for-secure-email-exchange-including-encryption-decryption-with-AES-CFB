import unittest
from ElgamalEcc.Curve import P256, Curve25519, Point, secp256k1
from Signature.Key import gen_keypair
from ElgamalEcc.ElGamal import ElGamal
from Aes.Aes import AES
from os import urandom
import binascii

plain_text = b'Group-29-Testing'
pri_key, pub_key = gen_keypair(secp256k1)
cipher_elg = ElGamal(secp256k1)
C1, C2 = cipher_elg.encrypt(plain_text, pub_key)
new_plaintext = cipher_elg.decrypt(pri_key, C1, C2)
print("*"*100)
print("ElgamalECC test")
print("-"*80)
print("private key:",pri_key)
print("public key:",pub_key)
print("message:",plain_text)
print("encrypted C1,C2")
print(C1)
print(C2)
print("-"*80)
print("Decry-message:",new_plaintext)


key = urandom(16)
iv = urandom(16)
aes = AES(key)
message = b'Group-29-Test'
print("*"*100)
print("AES-CFB test")
print("-"*80)
print("key:",key)
print("iv:",iv)
print("message:",message)
print("-"*80)
ciphertext = aes.encrypt_cfb(message,iv)

ciphertext=binascii.hexlify(ciphertext).decode()
iv = binascii.hexlify(iv).decode()
print(type(ciphertext))
ciphertext=binascii.unhexlify(ciphertext)
iv = binascii.unhexlify(iv)

dectext=aes.decrypt_cfb(ciphertext,iv)
print("*"*100)
