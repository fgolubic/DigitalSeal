'''
Created on May 7, 2019

@author: Filip
'''

from Lab2.DigitalEnvelope import DigitalEnvelope
from Lab2.DigitalSignature import DigitalSignature

class DigitalSeal:
        
        def __init__(self, sealFile, hashAlgorithm,  privateKeyE, symetricAlgorithm, secretKey, secretKeySize, mode, publicKey, keyLengthPub, keyLengthPriv, envelopeFile):
            
            self.envelope = DigitalEnvelope(symetricAlgorithm, secretKey, secretKeySize, mode, publicKey, keyLengthPub, envelopeFile)
            
            self.seal = DigitalSignature(sealFile, hashAlgorithm, keyLengthPriv, privateKeyE)
            
            
        def make(self, dataFile, outputFile):
            
            (cryptData, cryptKey) = self.envelope.make(dataFile, outputFile)
            
            self.seal.makeWithByte(cryptData + cryptKey, dataFile)