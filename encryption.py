from __future__ import unicode_literals

from tkinter import *
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog 
from tkinter import Entry

import urllib.parse
import urllib.request 
import re
import threading
import webbrowser
import stdiomask
import os
import time

import subprocess
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from tqdm import tqdm
from threading import Lock

root = tk.Tk()
root.title('Tish encryption software')
root.resizable(False, False)
root.geometry('300x230')




def browse_button():
    # Allow user to select a directory and store it in global var
    # called folder_path
    global folder_path
    filename = filedialog.askdirectory()
    folder_path.set(filename)
    print(filename)
    return folder_path


def encrypt_button():
   
     kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"E1.get()",
        iterations=100000,
        backend=default_backend())

     key = base64.urlsafe_b64encode(kdf.derive(b"E2.get()"))
     
     

     with open('my.key','wb') as mykey:
       mykey.write(key)

       f = Fernet(key)

   
     path=folder_path.get()
     for path,subdir,files in os.walk(path):
   
        for name in files:    
         print (os.path.join(path,name)) # will print path of files
         with open(os.path.join(path,name),'rb') as original_file:
                original = original_file.read()

                encrypted = f.encrypt(original)

         with open(os.path.join(path,name),'wb') as encrypted_file:
                 encrypted_file.write(encrypted)
         
                 print('\nAll files and folders in '+path+' are Encrypted.')
         max_val = 1000
         some_condition = True

         p = tqdm(total=max_val, disable=False)

         if f.encrypt(original):
            for i in range(max_val):
               time.sleep(0.01)
               p.update(1)
            p.close()


def decrypt_button():
     kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"E1.get()",
        iterations=100000,
        backend=default_backend())

     key = base64.urlsafe_b64encode(kdf.derive(b"E2.get()"))

     with open('my.key','wb') as mykey:
       mykey.write(key)

       f = Fernet(key)

   
     path=folder_path.get()
     for path,subdir,files in os.walk(path):
   
        for name in files:    
         print (os.path.join(path,name)) # will print path of files
         with open(os.path.join(path,name),'rb') as original_file:
                original = original_file.read()

                decrypted = f.decrypt(original)

         

         with open(os.path.join(path,name),'wb') as decrypted_file:
                 decrypted_file.write(decrypted)

                 

                 print('\nAll files and folders in '+path+' are Decrypted.')

         max_val = 1000
         some_condition = True

         p = tqdm(total=max_val, disable=False)

         if f.encrypt(original):
            for i in range(max_val):
               time.sleep(0.01)
               p.update(1)
            p.close()

folder_path = StringVar()

lbl1 = Label(master=root,textvariable=folder_path)
lbl1.pack(expand=True)



button2 = Button(text="Browse", command=browse_button)


button2.pack(expand=True)


lbl3 = Label(master=root, text="PASSWORD: ")
lbl3.pack(expand=True)
E2 = Entry(master=root, width=45)
E2.pack(expand=True)

lbl2 = Label(master=root, text="SALT: ")
lbl2.pack(expand=True)
E1 = Entry(master=root, width=45)
E1.pack(expand=True)
button3 = Button(text="ENCRYPT", command=encrypt_button)


button3.pack(expand=True)

button3 = Button(text="DECRYPT", command=decrypt_button)


button3.pack(expand=True)





root.mainloop()