#Will be managing both UI and the state of th widget in this file
#or can learn model view architecture to implement this design
#Views are basically the UI that will be rendered on the screen
#Models are the files that will be managing the state of the UI related data
#This code will be refactored for a Model View architecture

#we will be having 5 classed coressponding to 5 dialogs we have

from PyQt5.QtWidgets import QDialog,QApplication,QMainWindow
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import *
from PyQt5.uic import loadUi
from PyQt5 import uic
from cryptography.fernet import Fernet
from PyQt5 import QtGui
import sys
import random
import array

import hashlib
from hashlib import *
from zlib import adler32,crc32

from PyQt5.QtGui import QIcon



class Encryption(QMainWindow):
    def __init__(self):
        super(Encryption, self).__init__()
        loadUi("Encryption.ui",self)

        # these are the variables which we will be using
        self.inputText = ""
        self.outputText = ""

        # these are all the actions that we  will be using
        self.menu_action1 = QAction('#Encrypt', self)
        self.menu_action1.setData('Encrypt')
        self.menu_action1.triggered.connect(self.EncryptUP)


        self.menu_action3 = QAction('#EncryptKey', self)
        self.menu_action3.setData('EncryptKey')
        self.menu_action3.triggered.connect(self.EncryptKeyUP)

        self.menu_action4 = QAction('#DecryptKey', self)
        self.menu_action4.setData('DecryptKey')
        self.menu_action4.triggered.connect(self.DecryptKeyUP)

        self.menu_action5 = QAction('#StrongPassword', self)
        self.menu_action5.setData('StrongPassword')
        self.menu_action5.triggered.connect(self.PasswordUP)

        # attaching the actions to menuItems
        self.EncryptMenu.addAction(self.menu_action1)
        self.KEncryptMenu.addAction(self.menu_action3)
        self.KDecryptMenu.addAction(self.menu_action4)
        self.PasswordMenu.addAction(self.menu_action5)

        # these are the local actions belonging to the widget itself
        self.encryptButton.clicked.connect(self.btnPressed)
        #setting the font styling
        font = QtGui.QFont()
        font.setPointSize(10)
        self.InputEdit.setFont(font)
        self.OutputEdit.setFont(font)
    def btnPressed(self):
        try:
          self.inputText = self.InputEdit.toPlainText()
          self.hashAlgo=self.HashCombo.currentText()
          self.outputText=encryptText(self.inputText, self.hashAlgo)
          self.OutputEdit.setPlainText(self.outputText)
        except Exception as e:
            print(e)


    def ChangeIndex(self, index: int):
        widget.setCurrentIndex(index)

    def EncryptUP(self):
        widget.setCurrentIndex(0)

    def EncryptKeyUP(self):
        widget.setCurrentIndex(1)

    def DecryptKeyUP(self):
        widget.setCurrentIndex(2)

    def PasswordUP(self):
        widget.setCurrentIndex(3)

    # in here set the index based on the menu clicked

    def ChangeIndex(self,index:int):
        widget.setCurrentIndex(index)

    def HandleMenuClick(self):
        print("yes this is capturing the event")

class DecryptionKey(QMainWindow):
    def __init__(self):
        super(DecryptionKey, self).__init__()
        loadUi("DecryptKey.ui",self)

        # these are the variables which we will be using
        self.inputText = ""
        self.outputText = ""
        self.key=""

        # these are all the actions that we  will be using
        self.menu_action1 = QAction('#Encrypt', self)
        self.menu_action1.setData('Encrypt')
        self.menu_action1.triggered.connect(self.EncryptUP)


        self.menu_action3 = QAction('#EncryptKey', self)
        self.menu_action3.setData('EncryptKey')
        self.menu_action3.triggered.connect(self.EncryptKeyUP)

        self.menu_action4 = QAction('#DecryptKey', self)
        self.menu_action4.setData('DecryptKey')
        self.menu_action4.triggered.connect(self.DecryptKeyUP)

        self.menu_action5 = QAction('#StrongPassword', self)
        self.menu_action5.setData('StrongPassword')
        self.menu_action5.triggered.connect(self.PasswordUP)

        # attaching the actions to menuItems
        self.EncryptMenu.addAction(self.menu_action1)
        self.KEncryptMenu.addAction(self.menu_action3)
        self.KDecryptMenu.addAction(self.menu_action4)
        self.PasswordMenu.addAction(self.menu_action5)
        # these are the local actions belonging to the widget itself
        self.DecryptBtn.clicked.connect(self.btnPressed)
        font = QtGui.QFont()
        font.setPointSize(10)
        self.InputEdit.setFont(font)
        self.OutputEdit.setFont(font)
        self.KeyEdit.setFont(font)
    def btnPressed(self):
        self.inputText = self.InputEdit.toPlainText()
        self.key=self.KeyEdit.toPlainText()
        try:
            salt = bytes(self.key, encoding='utf-8')
            f = Fernet(salt)
            token = f.decrypt(bytes(self.inputText,encoding='utf-8')).decode('utf-8')
            self.OutputEdit.setPlainText(token)
        except Exception as e:
            print(e)
            self.OutputEdit.setPlainText('The tool ran into an error therfore teri maa ki chut hogayi!!')



        # add fernet decryption logic in here

    def ChangeIndex(self, index: int):
        widget.setCurrentIndex(index)

    def EncryptUP(self):
        widget.setCurrentIndex(0)

    def EncryptKeyUP(self):
        widget.setCurrentIndex(1)

    def DecryptKeyUP(self):
        widget.setCurrentIndex(2)

    def PasswordUP(self):
        widget.setCurrentIndex(3)



class EncryptionKey(QMainWindow):
    def __init__(self):
        super(EncryptionKey, self).__init__()
        loadUi("EncryptKeyUI.ui",self)

        # these are the variables which we will be using
        self.inputText = ""
        self.outputText = ""
        self.hashAlgo = ""
        self.key=""

        # these are all the actions that we  will be using
        self.menu_action1 = QAction('#Encrypt', self)
        self.menu_action1.setData('Encrypt')
        self.menu_action1.triggered.connect(self.EncryptUP)


        self.menu_action3 = QAction('#EncryptKey', self)
        self.menu_action3.setData('EncryptKey')
        self.menu_action3.triggered.connect(self.EncryptKeyUP)

        self.menu_action4 = QAction('#DecryptKey', self)
        self.menu_action4.setData('DecryptKey')
        self.menu_action4.triggered.connect(self.DecryptKeyUP)

        self.menu_action5 = QAction('#StrongPassword', self)
        self.menu_action5.setData('StrongPassword')
        self.menu_action5.triggered.connect(self.PasswordUP)

        # attaching the actions to menuItems
        self.EncryptMenu.addAction(self.menu_action1)
        self.KEncryptMenu.addAction(self.menu_action3)
        self.KDecryptMenu.addAction(self.menu_action4)
        self.PasswordMenu.addAction(self.menu_action5)
        # these are the local actions belonging to the widget itself
        self.EncryptBtn.clicked.connect(self.btnPressed)
        #setting the font styling
        font = QtGui.QFont()
        font.setPointSize(10)
        self.InputEdit.setFont(font)
        self.OutputEdit.setFont(font)
        self.KeyEdit.setFont(font)

    def btnPressed(self):
        self.hashAlgo = self.HashCombo.currentText()
        if self.hashAlgo != "Fernet":
            self.inputText = self.InputEdit.toPlainText()
            self.key = self.KeyEdit.toPlainText()
            self.outputText = encryptKeyText(self.inputText, self.hashAlgo, self.key,)
            try:
              self.OutputEdit.setPlainText(self.outputText)
            except Exception as e:
              print(e)
        else:
            self.inputText = self.InputEdit.toPlainText()
            data= encryptKeyText(self.inputText, self.hashAlgo, self.key,)
            try:
              self.OutputEdit.setPlainText(data['hash'])
              self.KeyEdit.setPlainText(data['key'])
            except Exception as e:
              print(e)



    def ChangeIndex(self, index: int):
        widget.setCurrentIndex(index)

    def EncryptUP(self):
        widget.setCurrentIndex(0)

    def EncryptKeyUP(self):
        widget.setCurrentIndex(1)

    def DecryptKeyUP(self):
        widget.setCurrentIndex(2)

    def PasswordUP(self):
        widget.setCurrentIndex(3)

    # in here set the index based on the menu clicked

    def ChangeIndex(self,index:int):
        widget.setCurrentIndex(index)

class givePassword(QMainWindow):
    def __init__(self):
        super(givePassword, self).__init__()
        loadUi("GivePassword.ui",self)

        #this will contain the strong generated password
        self.password=""

        # these are all the actions that we  will be using
        self.menu_action1 = QAction('#Encrypt', self)
        self.menu_action1.setData('Encrypt')
        self.menu_action1.triggered.connect(self.EncryptUP)

        self.menu_action3 = QAction('#EncryptKey', self)
        self.menu_action3.setData('EncryptKey')
        self.menu_action3.triggered.connect(self.EncryptKeyUP)

        self.menu_action4 = QAction('#DecryptKey', self)
        self.menu_action4.setData('DecryptKey')
        self.menu_action4.triggered.connect(self.DecryptKeyUP)

        self.menu_action5 = QAction('#StrongPassword', self)
        self.menu_action5.setData('StrongPassword')
        self.menu_action5.triggered.connect(self.PasswordUP)

        # attaching the actions to menuItems
        self.EncryptMenu.addAction(self.menu_action1)
        self.KEncryptMenu.addAction(self.menu_action3)
        self.KDecryptMenu.addAction(self.menu_action4)
        self.PasswordMenu.addAction(self.menu_action5)

        #these are the local actions associated with this widget
        self.PasswordBtn.clicked.connect(self.securePassword)
        font = QtGui.QFont()
        font.setPointSize(10)
        #setting the font styling
        self.PasswordText.setFont(font)
    def securePassword(self):
        try:
            MAX_LEN = 12
            DIGITS = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
            LOCASE_CHARACTERS = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                                 'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q',
                                 'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
                                 'z']

            UPCASE_CHARACTERS = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                 'I', 'J', 'K', 'M', 'N', 'O', 'p', 'Q',
                                 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
                                 'Z']

            SYMBOLS = ['@', '#', '$', '%', '=', ':', '?', '.', '/', '|', '~', '>',
                       '*', '(', ')', '<']
            COMBINED_LIST = DIGITS + UPCASE_CHARACTERS + LOCASE_CHARACTERS + SYMBOLS

            # randomly select at least one character from each character set above
            rand_digit = random.choice(DIGITS)
            rand_upper = random.choice(UPCASE_CHARACTERS)
            rand_lower = random.choice(LOCASE_CHARACTERS)
            rand_symbol = random.choice(SYMBOLS)
            temp_pass = rand_digit + rand_upper + rand_lower + rand_symbol
            for x in range(MAX_LEN - 4):
                temp_pass = temp_pass + random.choice(COMBINED_LIST)

                # convert temporary password into array and shuffle to
                # prevent it from having a consistent pattern
                # where the beginning of the password is predictable
                temp_pass_list = array.array('u', temp_pass)
                random.shuffle(temp_pass_list)

            # traverse the temporary password array and append the chars
            # to form the password
            password = ""
            for x in temp_pass_list:
                password = password + x

            # print out password
            self.PasswordText.setPlainText(password)
        except Exception as e:
            self.PasswordText.setPlainText('The application ran into an error so fuck off!')


    def ChangeIndex(self, index: int):
        widget.setCurrentIndex(index)

    def EncryptUP(self):
        widget.setCurrentIndex(0)

    def EncryptKeyUP(self):
        widget.setCurrentIndex(1)

    def DecryptKeyUP(self):
        widget.setCurrentIndex(2)

    def PasswordUP(self):
        widget.setCurrentIndex(3)

    # in here set the index based on the menu clicked

    def ChangeIndex(self,index:int):
        widget.setCurrentIndex(index)

#adding all the encryption and decryption algo in here


def SHA_256Hash(text):
    hash = sha256(text.encode())
    return {'originalString': text, 'hashedValue': hash.hexdigest()}

def SHA_224Hash(text):
    hash = sha224(text.encode())
    return {'originalString': text, 'hashedValue': hash.hexdigest()}

def SHA_512Hash(text):
    hash = sha512(text.encode())
    return {'originalString': text, 'hashedValue': hash.hexdigest()}

def SHA_384Hash(text):
    hash = sha384(text.encode())
    return {'originalString': text, 'hashedValue': hash.hexdigest()}

def SHA_1HASH(text):
    hash = sha1(text.encode())
    return {'originalString': text, 'hashedValue': hash.hexdigest()}

def SHA3_512Hash(text):
    hash = sha3_512(text.encode())
    return {'originalString': text, 'hashedValue': hash.hexdigest()}

def SHA3_384Hash(text):
    hash = sha3_384(text.encode())
    return {'originalString': text, 'hashedValue': hash.hexdigest()}

def SHA3_256Hash(text):
    hash = sha3_256(text.encode())
    return {'originalString': text, 'hashedValue': hash.hexdigest()}

def SHA3_224Hash(text):
    hash = sha3_224(text.encode())
    return {'originalString': text, 'hashedValue': hash.hexdigest()}

def SHAKE_256HASH(text):
    hash = shake_256(text.encode())
    return {'originalString': text, 'hashedValue': hash.hexdigest(64)}

def SHAKE_128HASH(text):
    hash = shake_128(text.encode())
    return {'originalString': text, 'hashedValue': hash.hexdigest(64)}

    # apparentl some of the hashes will not work on your OS
    # while calling the new constructor make sure that you are encoding your string first to bytes/octet

def sha512_224_HASH(text):
    text = text.encode('utf-8')
    hash_function = hashlib.new('sha512_224')
    hash_function.update(text)
    hash = hash_function.hexdigest()
    return {'originalString': text, 'hashedValue': hash}

def SHA_512_256_HASH(text):
    text = text.encode('utf-8')
    hash_function = hashlib.new('sha512_256')
    hash_function.update(text)
    hash = hash_function.hexdigest()
    return {'originalString': text, 'hashedValue': hash}

def MDC2_HASH(text):
    text = text.encode('utf-8')
    hash_function = hashlib.new('mdc2')
    hash_function.update(text)
    hash = hash_function.hexdigest()
    return {'originalString': text, 'hashedValue': hash}

def MD4_HASH(text):
    text = text.encode('utf-8')
    hash_function = hashlib.new('md4')
    hash_function.update(text)
    hash = hash_function.hexdigest()
    return {'originalString': text, 'hashedValue': hash}

def MD5_HASH(text):
    text = text.encode('utf-8')
    hash_function = hashlib.new('md5')
    hash_function.update(text)
    hash = hash_function.hexdigest()
    return {'originalString': text, 'hashedValue': hash}

def MD5_SHA1_HASH(text):
    text = text.encode('utf-8')
    hash_function = hashlib.new('md5-sha1')
    hash_function.update(text)
    hash = hash_function.hexdigest()
    return {'originalString': text, 'hashedValue': hash}

def Whirlpool_HASH(text):
    text = text.encode('utf-8')
    hash_function = hashlib.new('whirlpool')
    hash_function.update(text)
    hash = hash_function.hexdigest()
    return {'originalString': text, 'hashedValue': hash}

def RIPEMD_160_HASH(text):
    text = text.encode('utf-8')
    hash_function = hashlib.new('ripemd160')
    hash_function.update(text)
    hash = hash_function.hexdigest()
    return {'originalString': text, 'hashedValue': hash}

def blake2s_HASH(text):
    text = text.encode('utf-8')
    hash_function = hashlib.new('blake2s')
    hash_function.update(text)
    hash = hash_function.hexdigest()
    return {'originalString': text, 'hashedValue': hash}

def blake2b_HASH(text):
    text = text.encode('utf-8')
    hash_function = hashlib.new('blake2b')
    hash_function.update(text)
    hash = hash_function.hexdigest()
    return {'originalString': text, 'hashedValue': hash}

def SM3_HASH(text):
    text = text.encode('utf-8')
    hash_function = hashlib.new('sm3')
    hash_function.update(text)
    hash = hash_function.hexdigest()
    return {'originalString': text, 'hashedValue': hash}

    # these two algo are present in the zlib library and these two basically gives numeric hash instead of a hexadecimal value
def adler32_HASH(text):
    text = text.encode('utf-8')
    hash = adler32(text)
    return {'originalString': text, 'hashedValue': hash}

def cr32_HASH(text):
    text = text.encode('utf-8')
    hash = crc32(text)
    return {'originalString': text, 'hashedValue': hash}

def blake2sKey(text:str,salt:str):
    key=bytes(salt,encoding='utf-8')
    text = bytes(text, encoding='utf-8')
    h = blake2s(digest_size=32, key=key)
    h.update(text)
    return h.hexdigest().encode('utf-8')
def blake2bKey(text:str,salt:str):
    key = bytes(salt, encoding='utf-8')
    text = bytes(text, encoding='utf-8')
    h = blake2b(digest_size=32, key=key)
    h.update(text)
    return h.hexdigest().encode('utf-8')




def encryptText(text:str,algo:str):
    if algo == 'SHA256':
        try:
            return SHA_256Hash(text)['hashedValue']
        except Exception as e:
            return 'Your system does not support this alogithm'
    elif algo == 'SHA224':
        try:
           return SHA_224Hash(text)['hashedValue']
        except Exception as e:
            return 'Your system does not support this alogithm'
    elif algo == 'SHA512':
        try:
          return SHA_512Hash(text)['hashedValue']
        except Exception as e:
            return 'Your system does not support this alogithm'
    elif algo == 'SHA384':
        try:
          return SHA_384Hash(text)['hashedValue']
        except Exception as e:
            return 'Your system does not support this alogithm'
    elif algo == 'SHA1':
        try:
          return SHA_1HASH(text)['hashedValue']
        except Exception as e:
            return 'Your system does not support this alogithm'
    elif algo == 'SHA3_512':
        try:
          return SHA3_512Hash(text)['hashedValue']
        except Exception as e:
            return 'Your system does not support this alogithm'
    elif algo == 'SHA3_384':
        try:
          return SHA3_384Hash(text)['hashedValue']
        except Exception as e:
            return 'Your system does not support this alogithm'
    elif algo == 'SHA3_256':
        try:
          return SHA3_256Hash(text)['hashedValue']
        except Exception as e:
            return 'Your system does not support this alogithm'
    elif algo == 'SHA3_224':
        try:
          return SHA3_224Hash(text)['hashedValue']
        except Exception as e:
            return 'Your system does not support this alogithm'
    elif algo == 'SHAKE256':
        try:
          return SHAKE_256HASH(text)['hashedValue']
        except Exception as e:
            return 'Your system does not support this alogithm'
    elif algo == 'SHAKE128':
        try:
          return SHAKE_128HASH(text)['hashedValue']
        except Exception as e:
            return 'Your system does not support this alogithm'
    elif algo == 'SHA512_224':
        try:
          return sha512_224_HASH(text)['hashedValue']
        except Exception as e:
            return 'Your system does not support this alogithm'
    elif algo == 'SHA512_256':
        try:
          return SHA_512_256_HASH(text)['hashedValue']
        except Exception as e:
            return 'Your system does not support this alogithm'
    elif algo == 'MD2':
        try:
          return MDC2_HASH(text)['hashedValue']
        except Exception as e:
            return 'Your system does not support this alogithm'
    elif algo == 'MD4':
        try:
          return MD4_HASH(text)['hashedValue']
        except Exception as e:
            return 'Your system does not support this alogithm'
    elif algo == 'MD5':
        try:
          return MD5_HASH(text)['hashedValue']
        except Exception as e:
            return 'Your system does not support this alogithm'
    elif algo == 'MD5_SHA1':
        try:
          return MD5_SHA1_HASH(text)['hashedValue']
        except Exception as e:
            return 'Your system does not support this alogithm'
    elif algo == 'WHIRLPOOL':
        try:
          return Whirlpool_HASH(text)['hashedValue']
        except Exception as e:
            return 'Your system does not support this alogithm'
    elif algo == 'RIPEMD_160':
        try:
          return RIPEMD_160_HASH(text)['hashedValue']
        except Exception as e:
            return 'Your system does not support this alogithm'
    elif algo == 'BLAKE2S':
        try:
          return blake2s_HASH(text)['hashedValue']
        except Exception as e:
            return 'Your system does not support this alogithm'
    elif algo == 'BLAKE2B':
        try:
          return blake2b_HASH(text)['hashedValue']
        except Exception as e:
            return 'Your system does not support this alogithm'
    elif algo == 'SM3':
        try:
          return SM3_HASH(text)['hashedValue']
        except Exception as e:
            return 'Your system does not support this alogithm'
    elif algo == 'ADLER32':
        try:
          return adler32_HASH(text)['hashedValue']
        except Exception as e:
            return 'Your system does not support this alogithm'
    elif algo == 'CR32':
        try:
          return cr32_HASH(text)['hashedValue']
        except Exception as e:
            return 'Your system does not support this alogithm'



def encryptKeyText(text:str,algo:str,key:str="Roopa kii maa ka bhosda"):
    if algo == 'BLAKE2S':
        try:
          return blake2sKey(text,key).decode("utf-8")
        except Exception as e:
            return 'There was some error so fuck off'
    elif algo == 'BLAKE2B':
        try:
          return blake2bKey(text,key).decode("utf-8")
        except Exception as e:
            return 'There was some error so fuck off'
    elif  algo == 'Fernet':
        try:
            key = Fernet.generate_key()
            f = Fernet(key)
            token = f.encrypt(bytes(text,encoding='utf-8'))
            return {"key":key.decode("utf-8"),"hash":token.decode("utf-8")}
        except Exception as e:
            print(e)


app=QApplication(sys.argv)
widget=QtWidgets.QStackedWidget()
#creating the instances of our class
decryptKey=DecryptionKey()
encryption=Encryption()
encryptKey=EncryptionKey()
password=givePassword()

#adding these instance to the stacked widget
widget.addWidget(encryption)
widget.addWidget(encryptKey)
widget.addWidget(decryptKey)
widget.addWidget(password)


widget.setFixedWidth(929)
widget.setFixedHeight(480)
widget.show()

try:
    sys.exit(app.exec_())

except:
    print("Exiting the app!!")