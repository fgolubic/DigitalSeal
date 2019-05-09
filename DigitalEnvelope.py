'''
Created on May 6, 2019

@author: Filip
'''
import os
from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as pad
import base64
from Lab2.SupportFunctions import writeCryptedFile
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

class DigitalEnvelope:

    def __init__(self, symetricAlgorithm, secretKey, secretKeySize, mode, publicKey, keyLength, envelopeFile):
        
        self.symetricAlgorithmName = symetricAlgorithm
        self.secretKeySize = secretKeySize
        self.secretKey = secretKey
        self.publicKey = publicKey #(n, e) in RSA
        self.keyLength = keyLength # length of n in RSA
        self.envelopeFile = open(envelopeFile, "w")
        
        if symetricAlgorithm == 'AES':
            
            self.symetricAlgorithm = algorithms.AES(secretKey)
            self.blockSize = 128
        elif symetricAlgorithm == 'DES':
            
            self.symetricAlgorithm = algorithms.TripleDES(secretKey)
            self.blockSize = 64
            
        else:
            raise  Exception("Invalid symetric algorithm: " + symetricAlgorithm)
        
        self.iv = os.urandom(int(self.blockSize / 8))
        
        if mode == 'CBC':
            self.mode = modes.CBC(self.iv)
        elif mode == 'ECB':
            self.mode = modes.ECB()
        elif mode == 'OFB':
            self.mode = modes.OFB(self.iv)
        elif mode == 'CFB':
            self.mode = modes.CFB(self.iv) 
        else:
            raise Exception("Invalid mode: " + mode)
        
        self.modeName = mode
        
    def make(self, fileForEnc, encFile):
        
        self.envelopeFile.write("---BEGIN OS2 CRYPTO DATA---\nDescription:\n   Envelope\n\n\nFile name:\n   " + fileForEnc)
        
        self.envelopeFile.write("\n\n\nMethod:\n   " + self.symetricAlgorithmName + "\n   RSA\n\n\n")
        
        key1 = hex(self.secretKeySize)[2:]
        
        while len(key1) < 4:
            key1 = '0' + key1
            
        key2 = hex(self.keyLength)[2:]
        
        while len(key2)<4:
            key2 = '0' + key2 
        self.envelopeFile.write("Key length:\n   " + key1 + "\n   " + key2 + "\n\n\n")
    
        byte_file = open(fileForEnc, "rb").read()
        
        padder = pad.PKCS7(128).padder()

        byte_file = padder.update(byte_file) + padder.finalize()

        cipher = Cipher(algorithm = self.symetricAlgorithm, mode = self.mode, backend = default_backend())
        
        encryptor = cipher.encryptor()
        
        ct = encryptor.update(byte_file) + encryptor.finalize()
        
        b64 = str(base64.b64encode(ct))
        b64 = b64[2:len(b64) - 1]
        
        #save encrypted file
        writeCryptedFile(fileForEnc, ct, self.symetricAlgorithmName, self.secretKeySize, self.modeName, self.iv, encFile)

        self.envelopeFile.write("Mode:\n   "  + self.modeName + "\n\n\n")
        
        if not (self.mode == 'ECB'):
            
            iv = str(base64.b64encode(self.iv))
            
            self.envelopeFile.write("Initialization Vector:\n   " + iv[2:-1] + "\n\n\n")
            
            
        i = 0
        
        self.envelopeFile.write("Envelope data:\n")
        while True :
            
            if len(b64[i*60:]) < 60:
                self.envelopeFile.write("   " + b64[i*60:] + "\n\n\n")
                break
            
            self.envelopeFile.write("   " + b64[i*60:(i+1)*60] + "\n")
            i += 1

        #private_key = RSA.generate(self.keyLength, randfunc= None, e = self.publicKey)
        public_key = RSA.construct(self.publicKey)
        
        encryptor = PKCS1_OAEP.new(public_key)
        ciphertext = encryptor.encrypt(self.secretKey)

        
        b64Key = str(ciphertext.hex())
        
        i = 0
        self.envelopeFile.write("Envelope crypt key:\n")
        while True :
            
            if len(b64Key[i*60:]) < 60:
                self.envelopeFile.write("   " + b64Key[i*60:] + "\n\n\n")
                break
            
            self.envelopeFile.write("   " + b64Key[i*60:(i+1)*60] + "\n")
            i += 1
            
            
        self.envelopeFile.write("---END OS2 CRYPTO DATA---")
        
        return ct, ciphertext