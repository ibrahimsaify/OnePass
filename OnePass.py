#!/usr/bin/env python3

import os
import hashlib
import string
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import requests
import pyperclip
import subprocess

#Set Globals Master Key and the Default Backup Directory i.e /opt/backups
MASTER_KEY = b""
BACKUP_DIR = "/opt/backups"

def banner():
    print("""
       #################################################################
       #################################################################
       ##                                                             ##
       ##  ██████╗ ███╗   ██╗███████╗██████╗  █████╗ ███████╗███████╗ ##
       ## ██╔═══██╗████╗  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝ ##
       ## ██║   ██║██╔██╗ ██║█████╗  ██████╔╝███████║███████╗███████╗ ##
       ## ██║   ██║██║╚██╗██║██╔══╝  ██╔═══╝ ██╔══██║╚════██║╚════██║ ##
       ## ╚██████╔╝██║ ╚████║███████╗██║     ██║  ██║███████║███████║ ##
       ##  ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝ ##
       ##                                                             ##
       ##                                                        v2.0 ##  
       ## Developed By: Ibrahim Saify                                 ##
       ## https://github.com/ibrahimsaify                             ##
       #################################################################
       #################################################################
    """)
    


def setMasterKey():

    global MASTER_KEY
    
    while(True):

        print("----------------------------SET MASTER PASSWORD----------------------------------")
        print("\nYou may also use our customized Password Generator for setting Master Key")
        print("\nNote:Your Master Password will be padded upto 32 characters if length < 32")
        print("Your Password will be automatically copied to your clipboard")
        master_password = input("\nSet Master Password (NEVER FORGET!): ")
        key_length = len(master_password)

        if key_length > 32:
            print("\nPassword length exceeds 32 characters!")
        else:
            break

    if key_length < 32:
        padding_length = 32 - key_length
        padding = ''.join(random.choices(string.ascii_letters + string.digits, k=padding_length))
        master_password += padding
        MASTER_KEY = master_password.encode()
        print("\nYour Master Password has been padded up to 32 bytes!")
        pyperclip.copy(master_password)
        print(f"Password has been copied to your Clipboard! - {master_password}                 \n")
        subprocess.run(['notify-send','Master Password Copied','Your Master Password has been copied to your clipboard!'])
    else:
        MASTER_KEY = master_password.encode()    
    
    sha256_hash = hashlib.sha256()
    sha256_hash.update(master_password.encode('utf-8'))
    
    master_hash = sha256_hash.hexdigest()
    master_file = f"{BACKUP_DIR}/.master"
    
    with open(master_file,'w') as file:
        file.write(master_hash)
    
    print(f"Your Master file has been encrypted and saved at {master_file} \n")

    return

def checkMasterKey():

    global MASTER_KEY

    master_password = input("\nEnter your Master Password: ")
    master_file = f"{BACKUP_DIR}/.master"
    
    with open(master_file,'r') as file:
        master_hash = file.read()
    
    sha256_hash = hashlib.sha256()
    sha256_hash.update(master_password.encode('utf-8'))
    
    check_hash = sha256_hash.hexdigest()

    if (check_hash == master_hash):
        MASTER_KEY = master_password.encode()
        return
    else:
        print("\nIncorrect Master Password entered!! Exitting... ")
        exit()


def encrypt_password(password: str, key: bytes) -> bytes:

    iv=os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend = default_backend())
    encryptor = cipher.encryptor()

    padder=padding.PKCS7(128).padder()
    padded_password = padder.update(password.encode()) + padder.finalize()

    encrypted_password = encryptor.update(padded_password) + encryptor.finalize()

    return iv + encrypted_password

def decrypt_password(password: bytes, key: bytes) -> str:

    iv = password[:16]
    password = password[16:]

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend = default_backend())
    decryptor = cipher.decryptor()

    padded_password = decryptor.update(password) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    final_password = unpadder.update(padded_password) + unpadder.finalize()

    return final_password.decode()


def select_category():

    print("\nFor what application/service are you using this password for:")
    print("For eg. Instagram, Facebook, etc. ")
    print("\nCurrent Application Password Database (Blank output - Indicates No Passwords Saved)\n")
    files = os.listdir(BACKUP_DIR)
    for file in files:
        if file != ".master":
            print(file) 


    category=input("\nCategory: ")
    category_path=f"{BACKUP_DIR}/{category}"
    
    if not os.path.exists(category_path):
        os.mkdir(category_path)
    else:
        pass    
    print(f"\nPassword Database for {category}:-")
    for acc in os.listdir(category_path):
        print(acc)
    
    account_name=input("\nWho's this password for?(eg. John): ")
    filename=f"{category_path}/{account_name}"
    if not os.path.exists(filename):

        password=input(f"\nEnter the password that you want to save for {account_name}: ")
        saved_password = encrypt_password(password,MASTER_KEY)
        
        with open(filename,'wb') as file:
            file.write(saved_password)
        
        print(f"\n**  Your password for the Account {account_name} for {category} has been encrypted and saved!  **")
        print(f"\n**  Your password file is saved at {filename}  **\n")
    
        return
    else:

        print(f"\nYou already have a Password saved under this category for the Account {account_name}")
        overwrite = input("\nWould you like to overwrite and save a new password? (y/n): ")

        if overwrite == 'y':
            os.remove(filename)
            password=input("\nEnter the new password that you want to save (Enter exact password): ")
            saved_password = encrypt_password(password,MASTER_KEY)
        
            with open(filename,'wb') as file:
                file.write(saved_password)
        
            print(f"\n**  Your new password for the Account {account_name} for {category} has been encrypted and saved!**")
            print(f"\n**  Your new password file is saved at {filename}**\n")    
            return
        else:
            return           

        
def retrieve_password():

    #check if any categories exist
    if len(os.listdir(BACKUP_DIR)) == 0:
        print("\nYou have not yet created any application category for storing any passwords \n")
        print("\nPlease select the 1st option to save some passwords first")
        return

    print("\nYou currently have passwords saved for these categories/applications:\n")
    files = os.listdir(BACKUP_DIR)
    for file in files:
        if file != ".master":
            print(file)


    category = input("\nApplication for which you want to retrieve the Password (Case Sensitive): ")
    if os.path.exists(f"{BACKUP_DIR}/{category}"):
        if len(os.listdir(f"{BACKUP_DIR}/{category}")) == 0:
            print(f"\nNo account passwords to retrieve for {category}: ")
            print("\nPlease save some passwords first. (Select 1st Option and follow steps accordingly")
            return
        else:
            print("\nThese are the accounts whose encrypted passwords are already saved: \n")
            account_files = os.listdir(f"{BACKUP_DIR}/{category}")
            for account in account_files:
                print(account)


        account_name = input(f"\nWhose password do you want to retrieve for {category} (Case Sensitive): ")
        filename = f"{BACKUP_DIR}/{category}/{account_name}"
        if os.path.exists(filename):
            with open(filename,'rb') as passwd_file:
                passwd = passwd_file.read()
            decrypted_password = decrypt_password(passwd, MASTER_KEY)
            print(f"\n** The {category} Password for {account_name} is : {decrypted_password}  **\n")
            return
        else:
            print(f"\nNo Password has been saved for {account_name} for {category} ")
            print(f"\nIf you would like to save a password for {account_name} under {category}. Please select the first option and follow steps accordingly\n")
            return


    else:
        print("\nThis application/category doesn't exist and has no saved passwords! ")
        print("\nPlease select the 1st option to save some passwords first\n")
        return

def generate_password():

    print("\nWelcome to our customized Password Generator!")
    print("\nTo help you generate a strong password, you'll need to answer 2 questions for us")

    password = []
    tail = []
    
    while True:
        num_input = input("\nEnter a number having preferably more than 3 digits (NOT your birth year!): ")
        if num_input.isdigit():
            num = num_input
            break
        else:
            print("Invalid input. Please enter a number only (Preferably longer than 3 digits).")

    special_chars=['!', '#', '&', '*', '$', '_', '-', '@', '%', '^', ',', ')', '(', '>', '?', '<', '~', '{', '}', '[', ']', ';', '/']
    tail.append(''.join(random.sample(special_chars, 1)))
    tail.append(str(num))
    tail.append(''.join(random.sample(special_chars, 1)))
    tail = ''.join(tail)

    print("\nEnter a catchy phrase that's easy for you to remember: eg. (keep calm and exploit!)")
    phrase = input("Enter Phrase: ")
    phrase = phrase.replace(' ','')

    if len(phrase) >= 2:
        indices = random.sample(range(len(phrase)), 2)
    else:
        indices = []

    # Convert the selected characters to uppercase
    phrase = ''.join(c.upper() if i in indices else c for i, c in enumerate(phrase))
    phrase = phrase.replace('o','0').replace('e','3').replace('i','1')
    password.append(phrase)
    password.append(tail)

    password = ''.join(password)
    
    print("\nGreat! You have now generated a new and secure password using our customized algorithm! ")
    print(f"\nThe password generated based on what you provided is: {password}")
    pyperclip.copy(password)
    print("This has been automatically copied to your Clipboard!")
    print("\nIf you'd now like to save this password(in encrypted format) for future use, please select the 1st option")
    
    return


def update_password():

    #check if any categories exist
    if len(os.listdir(BACKUP_DIR)) == 0:
        print("\nYou have not yet created any application category for storing any passwords \n")
        print("\nPlease select the 1st option to save some passwords first")
        return

    print("\nYou currently have passwords saved for these categories/applications:\n")
    files = os.listdir(BACKUP_DIR)
    for file in files:
        if file != ".master":
            print(file)


    category = input("\nApplication for which you want to update the Password (Case Sensitive): ")
    if os.path.exists(f"{BACKUP_DIR}/{category}"):
        if len(os.listdir(f"{BACKUP_DIR}/{category}")) == 0:
            print(f"\nThere are no account passwords to update for {category}: ")
            print("\nPlease save some passwords first. (Select 1st Option and follow steps accordingly")
            return
        else:
            print("\nThese are the accounts whose encrypted passwords are already saved: \n")
            account_files = os.listdir(f"{BACKUP_DIR}/{category}")
            for account in account_files:
                print(account)


        account_name = input(f"\nWhose password do you want to update for {category} (Case Sensitive): ")
        filename = f"{BACKUP_DIR}/{category}/{account_name}"
        if os.path.exists(filename):
            os.remove(filename)
            password = input(f"\nEnter the new password that you want to update for {account_name}: ")
            saved_password = encrypt_password(password,MASTER_KEY)
        
            with open(filename,'wb') as file:
                file.write(saved_password)

            print(f"\n** Great! The {category} password for {account_name} has been Updated!! ** ")
            print(f"\n** The encrypted Password File has been backed up and saved at {filename}  **")
            return
        
        else:
            print(f"\nNo Password has been saved for {account_name} for {category} ")
            print(f"\nIf you would like to save a password for {account_name} under {category}, please select the 1st option\n")
            return    
    else:
        print("\nThis application/category doesn't exist and has no saved passwords! ")
        print("\nPlease select the 1st option to save some passwords first\n")
        return


def check_breach():
    #First Check if any categories exist
    if len(os.listdir(BACKUP_DIR)) == 0:
        print("\nYou have not yet created any application category for storing passwords \n")
        print("\nPlease select the 1st option to save some passwords first.")
        return

    print("\nYou currently have passwords saved for these categories/applications:\n")
    files = os.listdir(BACKUP_DIR)
    for file in files:
        if file != ".master":
            print(file)


    category = input("\nApplication for which you want to check if Password has been breached (Case Sensitive): ")
    if os.path.exists(f"{BACKUP_DIR}/{category}"):
        if len(os.listdir(f"{BACKUP_DIR}/{category}")) == 0:
            print(f"\nNo account passwords present for {category}: ")
            print("\nPlease save some passwords first. (Select 1st Option and follow steps accordingly")
            return
        else:
            print("\nThese are the accounts whose encrypted passwords are already saved: \n")
            account_files = os.listdir(f"{BACKUP_DIR}/{category}")
            for account in account_files:
                print(account)


        account_name = input(f"\nWhich account's password online breach do you want to check for {category} (Case Sensitive): ")
        filename = f"{BACKUP_DIR}/{category}/{account_name}"
        if os.path.exists(filename):
            with open(filename,'rb') as passwd_file:
                passwd = passwd_file.read()
            decrypted_password = decrypt_password(passwd, MASTER_KEY)
            #search request API Logic here

            hash = hashlib.sha1(decrypted_password.encode('utf-8')).hexdigest().upper()
            hash_prefix = hash[:5]
            url = f'https://api.pwnedpasswords.com/range/{hash_prefix}'
            r = requests.get(url)

            response = r.text

            hash_to_search = hash[5:]
            count = 0
            for line in response.splitlines():
                hash_value = line.split(':')[0]
    
                if hash_value == hash_to_search:
                    count = line.split(':')[1]
            
            if count == 0:
                print(f"\nGreat!! The {category} Password for {account_name} is secure and has not been breached/Pwned Online. ")
                return
            else:
                subprocess.run(['notify-send', 'Password Breached Online!', f'** The {category} Password for {account_name} has been breached/pwned {count} times online!! **'])
                print(f"\n** The {category} Password for {account_name} has been breached/pwned {count} times online!! **")
                print(f"\nYou should immediately change the {category} Password for {account_name} !!")
                print("\nPlease Select the 4th Option to Update your password to a more secure one.")
                return

        else:
            print(f"\nNo Password has been saved for {account_name} for {category} ")
            print(f"\nIf you would like to save a password for {account_name} under {category}. Please select the 1st option\n")
            return
    else:
        print("\nThis application/category doesn't exist and has no saved passwords! ")
        print("\nPlease select the 1st option to save some passwords first\n")
        return


if __name__ == '__main__':

    op = '0'
    banner()
    print("[+]Welcome to OnePass - A Password Manager tool for all your Password Services!! \n")
    
    if not os.path.exists(BACKUP_DIR):
        os.mkdir(BACKUP_DIR)
    else:
        pass
    
    if os.path.exists(f"{BACKUP_DIR}/.master"):
        checkMasterKey()
        pass
    else:
        setMasterKey()

    print("\nWhat operation would you like to perform:\n")
    
    while op != '7':
        print("Application's Password Database (Blank Indicates - No Passwords saved):-\n")    
        for file in os.listdir(BACKUP_DIR):
            if file != ".master":
                print(file)        
            
        print("\n[1]: Save and Backup a Password  ")
        print("[2]: Retrieve a Password  ")
        print("[3]: Generate a customized and secure Password (Customized according to you)")
        print("[4]: Change/Update Password")
        print("[5]: Check if a Password has been breached Online ")
        print("[6]: Clear Terminal Screen")
        print("[7]: Exit  ")
        
        op = input("\nChoice: ")
        if op == '1':

            select_category()
        
        elif op == '2':
            if len(os.listdir(BACKUP_DIR)) != 1:
                retrieve_password()            
            else:
                print("\nYou have no application category saved for which you can retrieve any Passwords")
        
        elif op == '3':
        
            generate_password()
        
        elif op == '4':
            if len(os.listdir(BACKUP_DIR)) != 1:
                update_password()            
            else:
                print("\nYou have no application category saved for which you can update any Passwords")

        elif op == '5':
            if len(os.listdir(BACKUP_DIR)) != 1:
                check_breach()            
            else:
                print("\nYou have no application category saved for which you can check Online Breach of any Password")

        elif op == '6':
            os.system("clear")

        elif op == '7':
            print("\n[-]Thank you for using OnePass - The Password Manager tool for your password services!! \n")
            exit()

        else:
            print("\nPlease enter a valid option number from 1 to 5 to perform the operations as stated above \n")    
        