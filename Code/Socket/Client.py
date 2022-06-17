import pickle
import socket
from os import urandom
from Aes.Aes import AES
from ElgamalEcc.Curve import secp256k1,Point
from ElgamalEcc.ElGamal import ElGamal
from datetime import datetime
import binascii

#the key signarute of the user.
PrivateKey=''
PublicKey=''
#Header msg length
HEADER_LENGTH = 10
#ip address and port of the server
IP = "127.0.0.1"
PORT = 1234
# Create a socket
# socket.AF_INET - address family, IPv4, some otehr possible are AF_INET6, AF_BLUETOOTH, AF_UNIX
# socket.SOCK_STREAM - TCP, conection-based, socket.SOCK_DGRAM - UDP, connectionless, datagrams, socket.SOCK_RAW - raw IP packets
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Connect to a given ip and port
client_socket.connect((IP, PORT))
# Set connection to non-blocking state, so .recv() call won;t block, just return some exception we'll handle
client_socket.setblocking(True)

def login(email,password):
    global PrivateKey
    global PublicKey
    #send to server login

    # Prepare username and header and send them
    # We need to encode username to bytes, then count number of bytes and prepare header of fixed size, that we encode to bytes as well

    msg = pickle.dumps({
        'command': "Login",
        'email': email,
        'password':password
    })
    msg = bytes(f'{len(msg):<{HEADER_LENGTH}}', 'utf-8') + msg
    client_socket.send(msg)
    server_response = listener()
    if server_response['Status'] == 'Fail':
        exit("Error-404, On login response.")
    else:
        keys = server_response['Response']
        PrivateKey, PublicKey = keys['privateKey'], keys['publicKey']
        return "logged in"


def sendmsg(source,to,message):
    #ask for sifnature public key (elgamal) of the reciver and encrypt msg by aes then encrypt key by ecc then send info.
    ciphertext,aes_key,iv=aes_encryp(message.encode('utf-8'))
    to_pub_key=convert_str_to_point(getpublickey(to))
    C1,C2=eccgmal_encryp(aes_key,to_pub_key)
    today = datetime.now().strftime("%d/%m/%Y,%H:%M")
    email_object={
        "source":source,
        "to":to,
        "cypherMessage":ciphertext,
        "c1":C1,
        "c2":C2,
        "iv":iv,
        "date":today
    }
    msg = pickle.dumps({
        "command": "Send_email",
        "email_object": email_object,
    })
    msg = bytes(f'{len(msg):<{HEADER_LENGTH}}', 'utf-8') + msg
    client_socket.send(msg)
    server_response = listener()
    if server_response['Status'] == 'Fail':
        exit("Error-404, On sendmsg response.")
    else:
        return


def getinbox(email):
    global PrivateKey
    PrivateKey = getprivatekey(email)
    msg = pickle.dumps({
        "command": "GetInbox",
        "email": email,
    })
    msg = bytes(f'{len(msg):<{HEADER_LENGTH}}', 'utf-8') + msg
    client_socket.send(msg)
    server_response = listener()
    if server_response['Status'] == 'Fail':
        exit("Error-404, On getinbox response.")
    else:
        list=convert_msgs(server_response['Response'])
        return list


def getpublickey(email):
    msg = pickle.dumps({
        "command": "GetKey",
        "email": email,
    })
    msg = bytes(f'{len(msg):<{HEADER_LENGTH}}', 'utf-8') + msg
    client_socket.send(msg)
    server_response=listener()
    print(server_response)
    if server_response['Status'] == 'Fail':
        exit("Error-404, On getkey response.")
    else:
        return server_response['Response']['publicKey']

def getprivatekey(email):
    msg = pickle.dumps({
        "command": "GetPrivateKey",
        "email": email,
    })
    msg = bytes(f'{len(msg):<{HEADER_LENGTH}}', 'utf-8') + msg
    client_socket.send(msg)
    server_response=listener()
    print(server_response)
    if server_response['Status'] == 'Fail':
        exit("Error-404, On getkey response.")
    else:
        return server_response['Response']['privateKey']

def listener():
    full_msg =b''
    new_msg =True
    while True:
        msg = client_socket.recv(4096)
        if new_msg:
            msglen = int(msg[:HEADER_LENGTH])
            new_msg = False
        full_msg += msg
        if len(full_msg)-HEADER_LENGTH == msglen:
            print("*" * 100)
            print("Message from server:")
            server_response=pickle.loads(full_msg[HEADER_LENGTH:])
            print(server_response)
            print("*"* 100+"\n")
            return server_response


def aes_encryp(message):
    key = urandom(16)
    iv = urandom(16)
    aes = AES(key)
    ciphertext = aes.encrypt_cfb(message, iv)
    ciphertext = binascii.hexlify(ciphertext).decode()
    iv = binascii.hexlify(iv).decode()
    return ciphertext,key,iv


def aes_decryp(ciphermessage,key,iv):
    aes = AES(key)
    ciphermessage=binascii.unhexlify(ciphermessage)
    iv = binascii.unhexlify(iv)
    dectext = aes.decrypt_cfb(ciphermessage, iv)
    return dectext


def eccgmal_encryp(aes_key,to_pub_key):
    cipher_elg = ElGamal(secp256k1)
    C1, C2 = cipher_elg.encrypt(aes_key, to_pub_key)
    return C1,C2


def eccgmal_decryp(C1,C2):
    cipher_elg = ElGamal(secp256k1)
    aes_key = cipher_elg.decrypt(int(PrivateKey), C1, C2)
    return aes_key

def convert_str_to_point(string):
    split=string.split("\n",2)
    x = int(split[0].split(" ")[1])
    y = int(split[1].split(" ")[1])
    point = Point(x,y,secp256k1)
    return point

def convert_msgs(string):
    dec_list=[]
    for msg in string:
        C1 = convert_str_to_point(msg[3])
        C2 = convert_str_to_point(msg[4])
        aes_key = eccgmal_decryp(C1,C2)
        decmsg=aes_decryp(msg[2],aes_key,msg[5])
        newmsg = {
            'msg': str(decmsg)[2:-1],
            'from': msg[0],
            'date': msg[6]
        }
        dec_list.append(newmsg)
    return dec_list

#check=login('rafa@gmail.com','rafa')
#sendmsg('roman@gmail.com',"dammmmm ittt check 2")

#check=login('roman@gmail.com','roman')
#print(check)
#response=getinbox('roman@gmail.com')
#print(response)
