'''
Created on May 9, 2019

@author: Filip
'''
from Lab2.SupportFunctions import readPrivateKey, readPublicKey, readEnvelope,\
    readSignature
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as pad
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHA224, SHA256, SHA384, SHA512
from Crypto.Signature import PKCS1_v1_5

#envelope file, crypted file, receiver public and private key files, expected decrypted file
def testEnvelope(envFile, pubFile, privFile, expectedFile):
    
    # fetch your private and public key from files
    privKeyL, privN, d = readPrivateKey(privFile)
    
    pubKeyL, pubN, e = readPublicKey(pubFile)
    
    #private and public n and bitwise length of n should be equal
    assert privN == pubN
    assert privKeyL == pubKeyL
    
    #reconstruct private key to work with Crypto
    private_key = RSA.construct((privN, e, d))
    
    fileName, simConf, rsaConf, data, cryptKey, mode, iv = readEnvelope(envFile)
    
    assert fileName == expectedFile
    
    pubMethod, pubKeyLength = rsaConf

    simMethod, simKeyLength = simConf

    
    assert pubMethod == 'RSA'
    assert pubKeyLength == pubKeyL
    
    decryptor = PKCS1_OAEP.new(private_key)
    secretKey = decryptor.decrypt(cryptKey)
    
    
    assert len(secretKey)*8 == simKeyLength
    
    if simMethod == 'AES':
            
            simMethod = algorithms.AES(secretKey)
            
    elif simMethod == 'DES':
            
            simMethod = algorithms.TripleDES(secretKey)
            
            
    else:
            raise  Exception("Invalid symetric algorithm: " + simMethod)
        
        
    if mode == 'CBC':
            mode = modes.CBC(iv)
    elif mode == 'ECB':
            mode = modes.ECB()
    elif mode == 'OFB':
            mode = modes.OFB(iv)
    elif mode == 'CFB':
            mode = modes.CFB(iv) 
    else:
            raise Exception("Invalid mode: " + mode)
        

    cipher = Cipher(algorithm = simMethod, mode = mode, backend = default_backend())

    decryptor = cipher.decryptor()

    dt = decryptor.update(data) + decryptor.finalize()

    unpadder = pad.PKCS7(128).unpadder()

    msg = unpadder.update(dt) + unpadder.finalize()
    
    realData = open(expectedFile, "rb").read()
    
    assert msg == realData
    print("ENVELOPE TEST SUCCESSFUL!")
    


def testSignature(signatureFile, originalFile, pubFile):
    
    pubKeyL, n, e = readPublicKey(pubFile)
    
    public_key = RSA.construct((n,e))
    
    verifier = PKCS1_v1_5.new(public_key) 
    
    fileName, hashed, key, signature = readSignature(signatureFile)
    
    (hashing, hashingKeyL) = hashed
    
    (enc, encKeyL) = key
    
    
    assert fileName == originalFile
    
    assert enc == 'RSA'
    
    assert encKeyL == pubKeyL
    
    hashAlgorithm = hashing + "-" + str(hashingKeyL)
    
    
    if hashAlgorithm == 'SHA-2-224':
            hashAlgorithm = SHA224.new()
                
    elif hashAlgorithm == 'SHA-2-256':
            hashAlgorithm = SHA256.new()
        
    elif hashAlgorithm == 'SHA-2-384':
            hashAlgorithm = SHA384.new()
            
    elif hashAlgorithm == 'SHA-2-512':
            hashAlgorithm = SHA512.new()
            
    elif hashAlgorithm == 'SHA-3-224':
            hashAlgorithm = SHA3_224.new()
            
    elif hashAlgorithm == 'SHA-3-256':
            hashAlgorithm = SHA3_256.new()
            
    elif hashAlgorithm == 'SHA-2-384':
            hashAlgorithm = SHA3_384.new()
            
    elif hashAlgorithm == 'SHA-2-256':
            hashAlgorithm = SHA3_512.new()
            
    else:
            raise Exception("Invalid hash function: " +  hashAlgorithm)
    
    
    data = open(originalFile,"rb").read()
    
    hashAlgorithm.update(data)
    
    assert verifier.verify(hashAlgorithm, signature)
    
    print("SIGNATURE TEST SUCCESSFUL!!")
    

def testSeal_verification(signatureFile, envelopeFile, pubFile):
    
    pubKeyL, n, e = readPublicKey(pubFile)
    
    public_key = RSA.construct((n,e))
    
    verifier = PKCS1_v1_5.new(public_key) 
    
    fileName, hashed, key, signature = readSignature(signatureFile)
    
    (hashing, hashingKeyL) = hashed
    
    (enc, encKeyL) = key
    
    
    
    assert enc == 'RSA'
    
    assert encKeyL == pubKeyL
    
    hashAlgorithm = hashing + "-" + str(hashingKeyL)
    
    
    if hashAlgorithm == 'SHA-2-224':
            hashAlgorithm = SHA224.new()
                
    elif hashAlgorithm == 'SHA-2-256':
            hashAlgorithm = SHA256.new()
        
    elif hashAlgorithm == 'SHA-2-384':
            hashAlgorithm = SHA384.new()
            
    elif hashAlgorithm == 'SHA-2-512':
            hashAlgorithm = SHA512.new()
            
    elif hashAlgorithm == 'SHA-3-224':
            hashAlgorithm = SHA3_224.new()
            
    elif hashAlgorithm == 'SHA-3-256':
            hashAlgorithm = SHA3_256.new()
            
    elif hashAlgorithm == 'SHA-2-384':
            hashAlgorithm = SHA3_384.new()
            
    elif hashAlgorithm == 'SHA-2-256':
            hashAlgorithm = SHA3_512.new()
            
    else:
            raise Exception("Invalid hash function: " +  hashAlgorithm)
    
    
    fileName, simConf, rsaConf, data, cryptKey, mode, iv = readEnvelope(envelopeFile)
    
    
    hashAlgorithm.update(data + cryptKey)
    
    assert verifier.verify(hashAlgorithm, signature)
    
    print("SEAL SIGNATURE TEST SUCCESSFUL!!")




testEnvelope("omotnica.txt", "rsa_b_javni.txt", "rsa_b_privatni.txt", "TestFile")
testSignature("potpis.txt", "TestFile", "rsa_a_javni.txt")
testSeal_verification("pecat.txt", "omotnica_pečata.txt", "rsa_a_javni.txt")
#test sealed envelope
testEnvelope("omotnica_pečata.txt", "rsa_b_javni.txt", "rsa_b_privatni.txt", "TestFile")
