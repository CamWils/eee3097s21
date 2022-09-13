from ctypes import sizeof
import json
from base64 import b64decode, b64encode
import sys
import csv
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
import time

input = ""

def data_input():
    data = " "
    file = open("tester.csv")
    csvreader = csv.reader(file)
    header = []
    header = next(csvreader)

    rows = []
    for row in csvreader:
        rows.append(row)

    totalRows = len(rows)
    print("Number of rows is: "+ str(totalRows))

    for x in header:
        data += x 
    print()
    for y in range(totalRows):
        data += str(rows[y])
    t0 = time.time()
    encrypt(data)
    t1 = time.time()

    total = t1 - t0
    print("Time: "+ str(total))

def encrypt(data):
    plaintext = bytes(data,encoding='utf-8')
    key = get_random_bytes(32)
    print("Key: "+str(key))
    cipher = ChaCha20.new(key=key)
    print("Plaintext: "+str(plaintext))
    ciphertext = cipher.encrypt(plaintext)
    print ("CipherText: "+str(ciphertext))
    nonce = b64encode(cipher.nonce).decode('utf-8')
    ct = b64encode(ciphertext).decode('utf-8')
    input = json.dumps({'nonce':nonce, 'ciphertext':ct})
    
    nonce_rfc7539 = get_random_bytes(12)
    cipher = ChaCha20.new(key=key, nonce=nonce_rfc7539)
    decryption(input,key)

def decryption(input_in,key_in):
    input = input_in
    key = key_in
    print("Decryption: ")
    # We assume that the key was somehow securely shared
    
    try:
        b64 = json.loads(input)
        nonce = b64decode(b64['nonce'])
        ciphertext = b64decode(b64['ciphertext'])
        cipher = ChaCha20.new(key=key, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        print("Decrypted Plaintext: " + str(plaintext))
    except (ValueError, KeyError):
        print("Incorrect decryption")


data_input()
