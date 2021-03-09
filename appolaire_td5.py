import os
import sys
import re
import tink
from tink import daead
from tink import cleartext_keyset_handle
from Cryptodome.Protocol.KDF import scrypt
from Cryptodome.Random import get_random_bytes


database = 'database.txt'
secret_key = 'secret_key.json'



#check if a database already exists, if not it creates a file
def init():
    if not os.path.exists("./" + database):
        open(database, 'x')



#add a KeysetHandle (or private key) to json file
def addKey(keyset_handle):
    with open(secret_key, "w") as file:
        our_writer = tink.JsonKeysetWriter(file)
        cleartext_keyset_handle.write(our_writer, keyset_handle)



#return private key from the json file
def readKey():
    with open(secret_key) as file:
        our_reader = tink.JsonKeysetReader(file.read())
        keyset_handle = cleartext_keyset_handle.read(our_reader)
    return keyset_handle



#to get the key when needed
def getKey():

    #if the json does not exists yet i.e no private key has been created
    if not os.path.exists("./" + secret_key):
        #daead is used to encrypt using AES SIV
        daead.register()
        keyset_handle = tink.new_keyset_handle(daead.deterministic_aead_key_templates.AES256_SIV)
        addKey(keyset_handle)

    #else i.e if a private key already exists in a json file
    else:
        keyset_handle = readKey()

    return keyset_handle



#check if user already exists in the database or if it respects the instructions of syntax (here: length and authorized characters)
def unique(user):
    file = open(database,'r').read().split('\n')[:-1]
    allUsernames = [line.split()[0] for line in file]
    syntax = bool(re.match('^[a-zA-Z0-9_]{4,25}$', user))
    return syntax and (user not in allUsernames)



#check if the length of a given password is longer than 8
def lengthPwd(pwd):
    return bool(re.match('^.{8}', pwd))



def encryption_machine(keyset_handle, plaintext ='', salt='', data=''):
    daead.register()        #register the aead deterministic primitives
    daead_primitive = keyset_handle.primitive(daead.DeterministicAead)  #get the primitive

    #if register : create a salt for the user, if login : use the salt in parameters
    if salt == '':
        salt = get_random_bytes(32)

    #hash the password using pyscript
    passwd = plaintext.encode('utf-8')
    #hashed_password = pyscrypt.hash(passwd, salt, 2048, 8, 1, 32)
    hashed_password = scrypt(passwd, salt, 16, N=2**14, r=8, p=1)


    #encrypt our data
    ciphertext = daead_primitive.encrypt_deterministically(hashed_password, data.encode())

    #get the ciphertext and the salt in hexa format to store them easily after
    ciphertext = ciphertext.hex()
    salt = salt.hex()
    return (str(ciphertext),str(salt))


#we store the username, their password and their associated password
def save_to_database(user, pwd, salt):
    with open(database, "a") as file:
        file.write(user + " " + pwd + " " + salt + "\n")




#get the salt from the database for a given user
def getSalt(user):
    file = open(database, 'r').read().split('\n')[:-1]
    allDatas = [line.split() for line in file]

    for data in allDatas:
        if data[0] == user:
            s = data[2]
            salt = bytes.fromhex(s)       #convert the salt back in bytes format to use it in encryption_machine()
            return salt



#check if the password given by a user when trying to log-in is correct
def check_password(user, pwd):
    file = open(database, 'r').read().split('\n')
    allDatas = [line.split() for line in file]
    del allDatas[-1]

    for data in allDatas :
        if data[0] == user:
            salt = getSalt(user)
            password = encryption_machine(getKey(),pwd,salt)[0]

            if password == data[1]:
                return True

    return False



def register():
    username = ''
    password = ''

    print("Username must be 4 to 25 characters long, and your password at least 8 characters long")
    print("If you do not follow these instructions, you will have to type in another one until instructions are followed")

    #check if the username entered by user respects the conditions (i.e uniqueness and syntax)
    while not unique(username):
        username = input('username : ')

    #check if the password respects the minimum length
    while not lengthPwd(password):
        password = input('password : ')

    #encrypt the given password once it is good, collect the encrypted pwd and the salt associated
    (pwd,salt) = encryption_machine(getKey(),password)

    #save everyhting in the database
    save_to_database(username,pwd,salt)

    print("You have been registered !")




def login():
    username = input('username : ')
    password = input('password : ')

    valid = check_password(username,password)

    if valid == False :
        print("Username or password incorrect. Are you sure you are registered ?")
    else :
        print("Connection successfull ! Hello " + username + " !")



if __name__ == "__main__":
    init()
    print("Hello !")

    keepGoing = '1'
    while keepGoing == '1':
        print("What would you like to do ?")
        option = input('1 register\n2 login\n3 quit\n')
        if option == '1':
            register()
        elif option == '2':
            login()
        elif option == '3':
            print("Goodbye!")
            sys.exit()

        keepGoing = input('Type 1 to keep going, type anything else other than 1 to quit : ')