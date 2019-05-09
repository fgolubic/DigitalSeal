'''
Created on May 8, 2019

@author: Filip
'''
from tkinter import *
from Lab2.DigitalEnvelope import DigitalEnvelope
from Lab2.DigitalSeal import DigitalSeal
from Lab2.DigitalSignature import DigitalSignature
from Lab2.SupportFunctions import *
import os

# Here, we are creating our class, Window, and inheriting from the Frame
# class. Frame is a class from the tkinter module. (see Lib/tkinter/__init__)
class Window(Frame):

    # Define settings upon initialization. Here you can specify
    def __init__(self, master=None):
        
        # parameters that you want to send through the Frame class. 
        Frame.__init__(self, master)   

        #reference to the master widget, which is the tk window                 
        self.master = master

        #with that, we want to then run init_window, which doesn't yet exist
        self.init_window()

    #Creation of init_window
    def init_window(self):

        win = self.master
    
        # prvi red
        message = "Ulazna datoteka:"
        Label(win, text=message).grid(row=1, column = 1) 
        ulaz_path = StringVar()
        self.ulazEntry = Entry(win, textvariable = ulaz_path, width = 20)
        ulaz_path.set('TestFile')
        self.ulazEntry.grid(row=1, column = 2)
    
        izlaz_path = StringVar()
        self.izlazEntry = Entry(win, textvariable = izlaz_path, width = 20)
        izlaz_path.set('./izlaz.txt')
        self.izlazEntry.grid(row=1, column = 3)
    
        #drugi red
        message = "Simetrični algoritam:"
        Label(win, text=message).grid(row=2, column = 1) 
        sim_path = StringVar()
        self.simEntry = Entry(win, textvariable = sim_path, width = 20)
        sim_path.set('AES-128')
        self.simEntry.grid(row=2, column = 2)
    
       
    
        #treci red
        message = "Tajni kljuc posiljatelja:"
        Label(win, text=message).grid(row=3, column = 1) 
        tajni_a_path = StringVar()
        self.tajniEntry = Entry(win, textvariable = tajni_a_path, width = 20)
        tajni_a_path.set('./a_tajni.txt')
        self.tajniEntry.grid(row=3, column = 2)
    
        Button(win, text='Generiraj', command=self.generateKey).grid(row=3, column = 3)
    
        #cetvrti red
        message = "Mode:"
        Label(win, text=message).grid(row=4, column = 1) 
        mode_path = StringVar()
        self.modeEntry = Entry(win, textvariable = mode_path, width = 20)
        mode_path.set('CBC')
        self.modeEntry.grid(row=4, column = 2)
    
    
        #peti red
        message = "Javni ključ primatelja:"  
        Label(win, text=message).grid(row=5, column = 1)  
        public_b_path = StringVar()
        self. public_b_Entry = Entry(win, textvariable =  public_b_path, width = 20)
        public_b_path.set('./rsa_b_javni.txt')
        self. public_b_Entry.grid(row=5, column = 2)

        # sesti red
        message = "Javni ključ:"
        Label(win, text=message).grid(row=6, column = 1) 
        pub_a_path = StringVar()
        self.pubEntry = Entry(win, textvariable = pub_a_path, width = 20)
        pub_a_path.set('./rsa_a_javni.txt')
        self.pubEntry.grid(row=6, column = 2)
        
        #sedmi red
        message = "Privatni ključ:"
        Label(win, text=message).grid(row=7, column = 1) 
        priv_a_path = StringVar()
        self.privEntry = Entry(win, textvariable = priv_a_path, width = 20)
        priv_a_path.set('./rsa_a_privatni.txt')
        self.privEntry.grid(row=7, column = 2)

        #osmi red
        message = "Hash:"
        Label(win, text=message).grid(row=8, column = 1) 
        hash_path = StringVar()
        self.hashEntry = Entry(win, textvariable = hash_path, width = 20)
        hash_path.set('SHA-2-256')
        self.hashEntry.grid(row=8, column = 2)
        
        #deveti red
        message = "Datoteka omotnice:"
        Label(win, text=message).grid(row=9, column = 1) 
        env_path = StringVar()
        self.envEntry = Entry(win, textvariable = env_path, width = 20)
        env_path.set('./omotnica_pečata.txt')
        self.envEntry.grid(row=9, column = 2)
        
        #deveti red
        message = "Datoteka pečata:"
        Label(win, text=message).grid(row=10, column = 1) 
        seal_path = StringVar()
        self.sealEntry = Entry(win, textvariable = seal_path, width = 20)
        seal_path.set('./pecat.txt')
        self.sealEntry.grid(row=10, column = 2)
    
        Button(win, text='Generiraj pečat', command=self.generateSeal).grid(row=11, column = 1, columnspan = 3)

       

    def generateKey(self):
        alg = self.simEntry.get().split('-')
        
        if alg[0] == 'DES':
            self.secretKey = os.urandom(int(56/8))
            writeSessionKey(alg, self.secretKey, self.tajniEntry.get())
            self.secretKeySize = 56
            
        elif alg[0] == 'AES':
            self.secretKey = os.urandom(int(int(alg[1])/8))
            
            writeSessionKey(alg[0], self.secretKey, self.tajniEntry.get(), int(alg[1]))
            
            self.secretKeySize = int(alg[1])
    
    def generateSeal(self):
        
        method, keyL, key = readSecretKey(self.tajniEntry.get())
        
        pubKeyLB, moduleB, pubB = readPublicKey(self.public_b_Entry.get())
        
        
        privKeyL, privModule, priv = readPrivateKey(self.privEntry.get())
        
        pubKeyL, module, pub = readPublicKey(self.pubEntry.get())
        
        final = DigitalSeal(self.sealEntry.get(), self.hashEntry.get(), (module, pub, priv), 
                            method, key, keyL, 
                            self.modeEntry.get(), (moduleB, pubB), pubKeyLB, privKeyL, 
                            self.envEntry.get())
        
        
        final.make(self.ulazEntry.get(), self.izlazEntry.get())
        
        
     

# root window created. Here, that would be the only window, but
# you can later have windows within windows.
root = Tk()
root.title("Digitalni pečat")
root.geometry("700x300")

#creation of an instance
app = Window(root)

#mainloop 
root.mainloop()  