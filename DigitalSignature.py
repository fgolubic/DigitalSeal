'''
Created on May 7, 2019

@author: Filip
'''
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHA224, SHA256, SHA384, SHA512


class DigitalSignature:
    
    def __init__(self, signatureFile, hashAlgorithm, keyLength, privateKeyE):
        
        self.signatureFile = open(signatureFile, "w")
        self.hashAlgorithmName = hashAlgorithm
        self.keyLength = keyLength 
        self.privateKey = privateKeyE #tuple of (n, e, d)
        
        if hashAlgorithm == 'SHA-2-224':
            self.hashAlgorithm = SHA224.new()
                
        elif hashAlgorithm == 'SHA-2-256':
            self.hashAlgorithm = SHA256.new()
        
        elif hashAlgorithm == 'SHA-2-384':
            self.hashAlgorithm = SHA384.new()
            
        elif hashAlgorithm == 'SHA-2-512':
            self.hashAlgorithm = SHA512.new()
            
        elif hashAlgorithm == 'SHA-3-224':
            self.hashAlgorithm = SHA3_224.new()
            
        elif hashAlgorithm == 'SHA-3-256':
            self.hashAlgorithm = SHA3_256.new()
            
        elif hashAlgorithm == 'SHA-2-384':
            self.hashAlgorithm = SHA3_384.new()
            
        elif hashAlgorithm == 'SHA-2-256':
            self.hashAlgorithm = SHA3_512.new()
            
        else:
            raise Exception("Invalid hash function: " +  hashAlgorithm)
        
        
    
    
    
    def make(self, fileForEnc):
        
        self.signatureFile.write("---BEGIN OS2 CRYPTO DATA---\nDescription:\n   Signature\n\n\nFile name:\n   " + fileForEnc)
        
        self.signatureFile.write("\n\n\nMethod:\n   " + self.hashAlgorithmName[0:5] + "\n   RSA\n\n\n")
        
        shaKeyL = str(hex(int(self.hashAlgorithmName[5:])))[3:]
        
        while not (len(shaKeyL) % 2 == 0):
            shaKeyL = '0' + shaKeyL
        
        rsaKeyL = str(hex(self.keyLength))[2:]
        
        while not (len(rsaKeyL) % 2 == 0):
            rsaKeyL = '0' + rsaKeyL
        
        
        self.signatureFile.write("Key length:\n   " + shaKeyL + "\n   " + rsaKeyL + "\n\n\n")
        
        data = open(fileForEnc, "rb").read()
        
        self.signatureFile.write("Signature:\n")
        
        
        
        self.hashAlgorithm.update(data)

        private_key = RSA.construct(self.privateKey)
        
        signer = PKCS1_v1_5.new(private_key) 
        
       
        ciphertext = signer.sign(self.hashAlgorithm)
        
        hexText = ciphertext.hex()
        
        i = 0
        
        while True:
            
            if len(hexText[i*60:]) < 60:
                self.signatureFile.write("   " + hexText[i*60:] + "\n\n\n")
                break
            
            self.signatureFile.write("   " + hexText[i*60:(i+1)*60] + "\n")
            i += 1
            
            
        self.signatureFile.write("---END OS2 CRYPTO DATA---")

        
        
    def makeWithByte(self, data, originalFile):
        
        self.signatureFile.write("---BEGIN OS2 CRYPTO DATA---\nDescription:\n   Seal\n\n\nFile name:\n   " + originalFile)
        
        self.signatureFile.write("\n\n\nMethod:\n   " + self.hashAlgorithmName[0:5] + "\n   RSA\n\n\n")
        
        shaKeyL = str(hex(int(self.hashAlgorithmName[5:])))[3:]
        
        while not (len(shaKeyL) % 2 == 0):
            shaKeyL = '0' + shaKeyL
        
        rsaKeyL = str(hex(self.keyLength))[2:]
        
        while not (len(rsaKeyL) % 2 == 0):
            rsaKeyL = '0' + rsaKeyL
        
        
        self.signatureFile.write("Key length:\n   " + shaKeyL + "\n   " + rsaKeyL + "\n\n\n")
        
        
        self.hashAlgorithm.update(data)
        #digest = self.hashAlgorithm.hexdigest()
        
        private_key = RSA.construct(self.privateKey)
        
        signer = PKCS1_v1_5.new(private_key) 
        
        #SMTH should always be None
        ciphertext = signer.sign(self.hashAlgorithm)
        
        self.signatureFile.write("Seal:\n")
        
        
        hexText = ciphertext.hex()
        
        i = 0
        
        while True:
            
            if len(hexText[i*60:]) < 60:
                self.signatureFile.write("   " + hexText[i*60:] + "\n\n\n")
                break
            
            self.signatureFile.write("   " + hexText[i*60:(i+1)*60] + "\n")
            i += 1
            
            
        self.signatureFile.write("---END OS2 CRYPTO DATA---")