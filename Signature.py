'''
Created on May 8, 2019

@author: Filip
'''
from tkinter import *
from Lab2.DigitalSignature import DigitalSignature
from Lab2.SupportFunctions import readPublicKey, readPrivateKey


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
        self.e = 65537
        # prvi red
        message = "Ulazna datoteka:"
        Label(win, text=message).grid(row=1, column = 1) 
        ulaz_path = StringVar()
        self.ulazEntry = Entry(win, textvariable = ulaz_path, width = 20)
        ulaz_path.set('TestFile')
        self.ulazEntry.grid(row=1, column = 2)

        # prvi red
        message = "Javni ključ:"
        Label(win, text=message).grid(row=2, column = 1) 
        pub_b_path = StringVar()
        self.pubEntry = Entry(win, textvariable = pub_b_path, width = 20)
        pub_b_path.set('./rsa_a_javni.txt')
        self.pubEntry.grid(row=2, column = 2)
        
        #treci red
        message = "Privatni ključ:"
        Label(win, text=message).grid(row=3, column = 1) 
        priv_a_path = StringVar()
        self.privEntry = Entry(win, textvariable = priv_a_path, width = 20)
        priv_a_path.set('./rsa_a_privatni.txt')
        self.privEntry.grid(row=3, column = 2)

        #cetvrti red
        message = "Hash:"
        Label(win, text=message).grid(row=4, column = 1) 
        hash_path = StringVar()
        self.hashEntry = Entry(win, textvariable = hash_path, width = 20)
        hash_path.set('SHA-2-256')
        self.hashEntry.grid(row=4, column = 2)

        #peti red
        message = "Potpis:"
        Label(win, text=message).grid(row=5, column = 1) 
        sign_path = StringVar()
        self.signEntry = Entry(win, textvariable = sign_path, width = 20)
        sign_path.set('./potpis.txt')
        self.signEntry.grid(row=5, column = 2)
    
        #6. Generiraj digitalni pecat
        Button(win, text='Potpisi', command=self.sign).grid(row=8, column = 1, columnspan = 3)
    
       
    def sign(self):
        
        privKeyL, privModule, priv = readPrivateKey(self.privEntry.get())
        pubKeyL, module, pub = readPublicKey(self.pubEntry.get())
        
        ds = DigitalSignature(self.signEntry.get(), self.hashEntry.get(), privKeyL, (module, pub, priv))
        
        ds.make(self.ulazEntry.get())


# root window created. Here, that would be the only window, but
# you can later have windows within windows.
root = Tk()
root.title("Digitalni potpis")
root.geometry("360x180")

#creation of an instance
app = Window(root)

#mainloop 
root.mainloop()  