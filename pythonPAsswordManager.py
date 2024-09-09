import csv
import os
import base64
import getpass
import hashlib
from cryptography.fernet import Fernet
import secrets
import string

# File paths
passwordFile = 'passwords.csv'
masterPasswordHashFile = 'master_password.hash'

# Encryption/Decryption setup
def generateEncryptionKey(password):
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def encryptPassword(key, password):
    fernet = Fernet(key)  #creates a key
    return fernet.encrypt(password.encode()).decode()

def decryptPassword(key, encryptedPassword):
    fernet = Fernet(key)
    return fernet.decrypt(encryptedPassword.encode()).decode()

# Master Password Setup
def getMasterPasswordHash():
    if os.path.exists(masterPasswordHashFile):
        with open(masterPasswordHashFile, 'r') as f:
            return f.read().strip()
    return None

def setMasterPassword():
    masterPassword = getpass.getpass("Set a new master password: ")
    hashedPassword = hashlib.sha256(masterPassword.encode()).hexdigest()
    with open(masterPasswordHashFile, 'w') as f:
        f.write(hashedPassword)

def authenticateUser():
    storedHash = getMasterPasswordHash()
    if not storedHash:
        print("No master password set. Let's set one.")
        setMasterPassword()
        storedHash = getMasterPasswordHash()

    while True:
        inputPassword = getpass.getpass("Enter master password: ")
        inputHash = hashlib.sha256(inputPassword.encode()).hexdigest()
        if inputHash == storedHash:
            return inputPassword
        else:
            print("Incorrect password. Try again.")

# Password Manager Functions
def addPassword(masterPassword):
    accountName = input("Enter account name (e.g., email, social media): ")
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")

    key = generateEncryptionKey(masterPassword)
    encryptedPassword = encryptPassword(key, password)

    with open(passwordFile, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([accountName, username, encryptedPassword])

    print(f"Password for {accountName} added successfully!")

def viewPasswords(masterPassword):
    if not os.path.exists(passwordFile):
        print("No passwords saved yet.")
        return

    key = generateEncryptionKey(masterPassword)
    with open(passwordFile, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            accountName, username, encryptedPassword = row
            print(f"Account: {accountName} | Username: {username}")
            choice = input("Reveal password? (y/n): ")
            if choice.lower() == 'y':
                password = decryptPassword(key, encryptedPassword)
                print(f"Password: {password}")

def deletePassword():
    accountNameToDelete = input("Enter the account name to delete: ")
    updatedRows = []
    found = False

    with open(passwordFile, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            if row[0] == accountNameToDelete:
                found = True
            else:
                updatedRows.append(row)

    if not found:
        print(f"No entry found for account: {accountNameToDelete}")
        return

    with open(passwordFile, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(updatedRows)

    print(f"Password for {accountNameToDelete} deleted successfully!")

def updatePassword(masterPassword):
    accountNameToUpdate = input("Enter the account name to update: ")
    updatedRows = []
    found = False

    key = generateEncryptionKey(masterPassword)
    with open(passwordFile, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            if row[0] == accountNameToUpdate:
                found = True
                username = row[1]
                newPassword = getpass.getpass("Enter new password: ")
                encryptedPassword = encryptPassword(key, newPassword)
                updatedRows.append([accountNameToUpdate, username, encryptedPassword])
            else:
                updatedRows.append(row)

    if not found:
        print(f"No entry found for account: {accountNameToUpdate}")
        return

    with open(passwordFile, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(updatedRows)

    print(f"Password for {accountNameToUpdate} updated successfully!")

# Password Generator
def generateStrongPassword(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for i in range(length))

# Main code
print("***** Password Manager *****")
masterPassword = authenticateUser()

while True:
    print("\nOptions:")
    print("1. Add a new password")
    print("2. View saved passwords")
    print("3. Update a password")
    print("4. Delete a password")
    print("5. Generate a strong password")
    print("6. Exit")

    choice = input("Select an option: ")

    if choice == '1':
        addPassword(masterPassword)
    elif choice == '2':
        viewPasswords(masterPassword)
    elif choice == '3':
        updatePassword(masterPassword)
    elif choice == '4':
        deletePassword()
    elif choice == '5':
        length = int(input("Enter desired password length: "))
        print(f"Generated password: {generateStrongPassword(length)}")
    elif choice == '6':
        print("Program ended succesfully!")
        break
    else:
        print("Invalid choice, try again.")