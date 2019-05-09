'''
Created on May 8, 2019

@author: Filip
'''
from tkinter import *
from Lab2.DigitalSignature import DigitalSignature
from Lab2.SupportFunctions import writeRSAprivateKey, writeRSApublicKey

from Crypto.PublicKey import RSA


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
        message = "Privatni ključ:"
        Label(win, text=message).grid(row=1, column = 1) 
        private_path = StringVar()
        self.privateEntry = Entry(win, textvariable = private_path, width = 20)
        private_path.set('./rsa_a_privatni.txt')
        self.privateEntry.grid(row=1, column = 2)
    
        #drugi red
        message = "Javni ključ:"
        Label(win, text=message).grid(row=2, column = 1) 
        public_path = StringVar()
        self.publicEntry = Entry(win, textvariable = public_path, width = 20)
        public_path.set('./rsa_a_javni.txt')
        self.publicEntry.grid(row=2, column = 2)
    
       
    
        #treci red
        message = "Duljina ključa:"
        Label(win, text=message).grid(row=3, column = 1) 
        len_path = StringVar()
        self.lenEntry = Entry(win, textvariable = len_path, width = 20)
        len_path.set('1024')
        self.lenEntry.grid(row=3, column = 2)
    
    
        #cetvrti red
        message = "Javni eksponent:"
        Label(win, text=message).grid(row=4, column = 1) 
        mode_path = StringVar()
        self.modeEntry = Entry(win, textvariable = mode_path, width = 20)
        mode_path.set('65537')
        self.modeEntry.grid(row=4, column = 2)
    
        #6. Generiraj digitalni pecat
        Button(win, text='Generiraj', command=self.generate).grid(row=5, column = 1, columnspan = 3)
    
       
    def generate(self):
        
        private_key = RSA.generate(int(self.lenEntry.get()), randfunc = None, e = int(self.modeEntry.get()))
        
        writeRSAprivateKey(int(self.lenEntry.get()), private_key.n, private_key.d, self.privateEntry.get())
        writeRSApublicKey(int(self.lenEntry.get()), private_key.n, private_key.e, self.publicEntry.get())
        


# root window created. Here, that would be the only window, but
# you can later have windows within windows.
root = Tk()
root.title("RSA Generator")
root.geometry("360x180")

#creation of an instance
app = Window(root)

#mainloop 
root.mainloop()  