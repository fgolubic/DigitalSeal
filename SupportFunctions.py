'''
Created on May 7, 2019

@author: Filip
'''
import base64


def writeSessionKey(algorithm,  key, keyFile, keyLength = None):
    
        fileD = open(keyFile, "w")
        
        
        fileD.write("---BEGIN OS2 CRYPTO DATA---\nDescription:\n   Secret key\n\n\nMethod:\n   " + algorithm + "\n\n\n")
        
        if algorithm == 'AES':
                fileD.write("Key length:\n   ")
                
                kl = str(hex(keyLength)[2:])
                
                while not (len(kl) % 2 == 0):
                    kl = '0' + kl
                    
                fileD.write(kl + "\n\n\n")
                
        fileD.write("Secret key:\n   " + str(key.hex()))
        fileD.write("\n\n\n---END OS2 CRYPTO DATA---")
        
def writeRSApublicKey(keyLength, modulus, e, keyFile):
    
        fileD = open(keyFile, "w")
        
        
        fileD.write("---BEGIN OS2 CRYPTO DATA---\nDescription:\n    Public key\n\n\nMethod:\n   RSA\n\n\nKey length:\n   ")
        
        
        kl = str(hex(keyLength)[2:])
                
        while not (len(kl) % 2 == 0):
            kl = '0' + kl
                    
        fileD.write(kl + "\n\n\nModulus:\n")
        
        kl = str(hex(modulus)[2:])
                
        i=0
        
        while True :
            
                if len(kl[i*60:]) < 60:
                    fileD.write("   " + kl[i*60:] + "\n\n\n")
                    break
            
                fileD.write("   " + kl[i*60:(i+1)*60] + "\n")
                i += 1
    
    
        fileD.write("Public exponent:\n   ")
        
        kl = str(hex(e)[2:])
                
        while not (len(kl) % 2 == 0):
            kl = '0' + kl
            
        fileD.write(kl + "\n\n\n---END OS2 CRYPTO DATA---")
        
        
def writeRSAprivateKey(keyLength, modulus, d, keyFile):
    
        fileD = open(keyFile, "w")
        
        
        fileD.write("---BEGIN OS2 CRYPTO DATA---\nDescription:\n    Private key\n\n\nMethod:\n   RSA\n\n\nKey length:\n   ")
        
        
        kl = str(hex(keyLength)[2:])
                
        while not (len(kl) % 2 == 0):
            kl = '0' + kl
                    
        fileD.write(kl + "\n\n\nModulus:\n")
        
        kl = str(hex(modulus)[2:])
                
        i=0
        
        while True :
            
                if len(kl[i*60:]) < 60:
                    fileD.write("   " + kl[i*60:] + "\n\n\n")
                    break
            
                fileD.write("   " + kl[i*60:(i+1)*60] + "\n")
                i += 1
    
        fileD.write("Private exponent:\n")
        
        kl = str(hex(d)[2:])
                
        i=0
        
        while True :
            
                if len(kl[i*60:]) < 60:
                    fileD.write("   " + kl[i*60:] + "\n\n\n")
                    break
            
                fileD.write("   " + kl[i*60:(i+1)*60] + "\n")
                i += 1
            
        fileD.write("---END OS2 CRYPTO DATA---")
       
def writeCryptedFile(fileName, data, algorithm, keyLength, mode, initVector, file): 
    
    fileD = open(file, "w")
        
        
    fileD.write("---BEGIN OS2 CRYPTO DATA---\nDescription:\n    Crypted File\n\n\nMethod:\n   "  + algorithm + "\n\n\n")
    
    if algorithm == 'AES':
        
        kl = str(hex(keyLength)[2:])
        
        while not (len(kl) % 2 == 0):
            kl = '0' + kl
            
        b64 = str(base64.b64encode(initVector))
        
        fileD.write("Key length:\n   " + kl +"\n\n\nMode:\n   "  + mode + "\n\n\n")
        
        if not (mode == 'ECB'):
            
            fileD.write("Initialization Vector:\n   " + b64[2:-1] + "\n\n\n")
            
            
        fileD.write("File name:\n   " + fileName + "\n\n\nFile data:\n")
        
        
        b64Key = str(base64.b64encode(data))
        b64Key = b64Key[2:len(b64Key) - 1]
        
        i = 0
        
        while True :
            
            if len(b64Key[i*60:]) < 60:
                fileD.write("   " + b64Key[i*60:] + "\n\n\n")
                break
            
            fileD.write("   " + b64Key[i*60:(i+1)*60] + "\n")
            i += 1
            
        
        fileD.write("---END OS2 CRYPTO DATA---")
        
    
    
def readPrivateKey(file):
    
    
    fileD = open(file, "r")


    while not fileD.readline().strip() == 'Key length:':
        continue
    
    keyLength = int('0x' + fileD.readline().strip(),  16)
    
    while not fileD.readline().strip() == 'Modulus:':
        continue
    
    
    modul = ''
    l = fileD.readline().strip()
    
    while not l == 'Private exponent:':
        
        modul = modul + l
        
        l = fileD.readline().strip()
        

    l = fileD.readline().strip()
    priv = ''
    
    while not l == '':
        
        priv += l
        
        l = fileD.readline().strip()
        
        
    return keyLength, int(modul, 16), int(priv, 16)


def readPublicKey(file):
    
     
    
    fileD = open(file, "r")


    while not fileD.readline().strip() == 'Key length:':
        continue
    
    keyLength = int('0x' + fileD.readline().strip(),  16)
    
    while not fileD.readline().strip() == 'Modulus:':
        continue
    
    
    modul = ''
    l = fileD.readline().strip()
    
    while not l == 'Public exponent:':
        
        modul = modul + l
        
        l = fileD.readline().strip()
        

    l = fileD.readline().strip()
    priv = ''
    
    while not l == '':
        
        priv += l
        
        l = fileD.readline().strip()
        
        
    return keyLength, int(modul, 16), int(priv, 16)
    
    
    
def readSecretKey(file):

    fileD = open(file, "r")


    while not fileD.readline().strip() == 'Method:':
        continue
    
    method = fileD.readline().strip()
    
    
    
    if method == 'DES':
        
        keyL = 56
        
        while not fileD.readline().strip() == 'Secret key:':
            continue
        
        key = int(fileD.readline().strip(),16)
        
        
    elif method == 'AES':
        
        while not fileD.readline().strip() == 'Key length:':
            continue
        
        keyL = int(fileD.readline().strip(), 16)
        
        while not fileD.readline().strip() == 'Secret key:':
            continue
        
        key = bytes.fromhex(fileD.readline().strip())
    
    
    
    return method, keyL, key
    

def readCryptedFile(file):
    
    fileD = open(file, "r")
    
    while not fileD.readline().strip() == 'Method:':
        continue
    
    
    method = fileD.readline().strip()
    
    
    
    if method == 'DES':
        
        keyL = 56
        
        
        
    elif method == 'AES':
        
        while not fileD.readline().strip() == 'Key length:':
            continue
        
        keyL = int(fileD.readline().strip(), 16)
    
    
    while not fileD.readline().strip() == 'Mode:':
        continue
    
    mode = fileD.readline().strip()
    
    
    if not mode == 'ECB':
        
        while not fileD.readline().strip() == 'Initialization Vector:':
            continue
    
        iv = fileD.readline().strip().encode()
        
    else:
        iv = None
    
    
    while not fileD.readline().strip() == 'File name:':
        continue
    
    fileName = fileD.readline().strip()
    
    while not fileD.readline().strip() == 'File data:':
        continue
    
    l = fileD.readline().strip()
    data = ''
    
    while not l == '':
        
        data += l
        
        l = fileD.readline().strip()
        
        
    return method, keyL, mode, iv, fileName, base64.b64decode(data)


def readSignature(file):
    
    
    fileD = open(file, "r")
    
    while not fileD.readline().strip() == 'File name:':
        continue
    
    fileName = fileD.readline().strip()
    
    while not fileD.readline().strip() == 'Method:':
        continue
    
    
    hashing = fileD.readline().strip()
    enc = fileD.readline().strip()
    
    
    while not fileD.readline().strip() == 'Key length:':
        continue
    
    
    hashingKeyL = int(fileD.readline().strip(), 16)
    encKeyL = int(fileD.readline().strip(), 16)
    
    temp = fileD.readline().strip()
    while not  (temp == 'Signature:' or temp == 'Seal:'):
        temp = fileD.readline().strip()
        continue
    
    
    l = fileD.readline().strip()
    signature = ''
    
    while not l == '':
        
        signature += l
        
        l = fileD.readline().strip()
        
        
    return fileName, (hashing, hashingKeyL), (enc, encKeyL), bytes.fromhex(signature) 


def readEnvelope(file):
    
    fileD = open(file, "r")
    
    while not fileD.readline().strip() == 'File name:':
        continue
    
    fileName = fileD.readline().strip()
    
    while not fileD.readline().strip() == 'Method:':
        continue
    
    
    privEnc = fileD.readline().strip()
    enc = fileD.readline().strip()
    
    
    while not fileD.readline().strip() == 'Key length:':
        continue
    
    
    privEncL = int(fileD.readline().strip(), 16)
    encKeyL = int(fileD.readline().strip(), 16)
    
    while not fileD.readline().strip() == 'Mode:':
        continue
    
    mode = fileD.readline().strip()
    
    
    if not mode == 'ECB':
        
        while not fileD.readline().strip() == 'Initialization Vector:':
            continue
    
        iv = base64.b64decode(fileD.readline().strip())
       
    else:
        iv = None
    
    while not fileD.readline().strip() == 'Envelope data:':
        continue
    
    
    l = fileD.readline().strip()
    env = ''
    
    while not l == '':
        
        env += l
        
        l = fileD.readline().strip()
        
    
    while not fileD.readline().strip() == 'Envelope crypt key:':
        continue
    
    
    l = fileD.readline().strip()
    cryptKey = ''
    
    while not l == '':
        
        cryptKey += l
        
        l = fileD.readline().strip()
    
    return fileName, (privEnc, privEncL), (enc, encKeyL), base64.b64decode(env), bytes.fromhex(cryptKey), mode, iv
