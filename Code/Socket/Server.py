import pickle
import socket
from Sql import Database
from ElgamalEcc.Curve import secp256k1
from Signature.Key import gen_keypair
from ElgamalEcc.ElGamal import ElGamal

# the database object
database = Database

# Header msg length
HEADER_LENGTH = 10

# ip address and port of the server
IP = "127.0.0.1"
PORT = 1234

# Create a socket
# socket.AF_INET - address family, IPv4, some otehr possible are AF_INET6, AF_BLUETOOTH, AF_UNIX
# socket.SOCK_STREAM - TCP, conection-based, socket.SOCK_DGRAM - UDP, connectionless, datagrams, socket.SOCK_RAW - raw IP packets
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# SO_ - socket option
# SOL_ - socket option level
# Sets REUSEADDR (as a socket option) to 1 on socket
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# Bind, so server informs operating system that it's going to use given IP and port
# For a server using 0.0.0.0 means to listen on all available interfaces, useful to connect locally to 127.0.0.1 and remotely to LAN interface IP
server_socket.bind((IP, PORT))

# This makes server listen to new connections
server_socket.listen(10)

print(f'Listening for connections on {IP}:{PORT}...')
clientsocket, address = server_socket.accept()


def command(data):
    data_variable = pickle.loads(data[HEADER_LENGTH:])
    print(data_variable)
    if data_variable['command'] == "Login":
        return login(data_variable['email'], data_variable['password'])
    if data_variable['command'] == "GetInbox":
        return get_inbox(data_variable['email'])
    if data_variable['command'] == "GetKey":
        return get_key(data_variable['email'])
    if data_variable['command'] == "GetPrivateKey":
        return get_private_key(data_variable['email'])
    if data_variable['command'] == "Send_email":
        return send_email(data_variable['email_object'])
    return "Fail", "Error wrong command"


def login(email, password):
    result = database.login(email)  # result is a list [email,pass,private key,public key]
    if result != "None" and result[0][1] == password:
        keys = {
            "privateKey": result[0][2],
            "publicKey": result[0][3]
        }
        return "Pass", keys
    else:
        if result != "None":
            print("Error User do not exists")
            return "Fail", "Error User do not exists"
        else:
            print("Error wrong password")
            return "Fail", "Error wrong password"


def send_email(email_object):
    result = database.send_email(email_object)
    if result != "None":
        return "Pass", result
    else:
        return "Fail", "Error wrong email"


def get_key(email):
    result = database.get_key(email)  # result is a list [email,pass,private key,public key]
    if result != "None":
        key = {
            "publicKey": result[0][3]
        }
        return "Pass", key
    else:
        print("Error User do not exists")
        return "Fail", "Error User do not exists"


def get_private_key(email):
    result = database.get_private_key(email)  # result is a list [email,pass,private key,public key]
    if result != "None":
        key = {
            "privateKey": result[0][2]
        }
        return "Pass", key
    else:
        print("Error User do not exists")
        return "Fail", "Error User do not exists"


def get_inbox(email):
    result = database.get_inbox(email)
    if result != "None":
        return "Pass", result
    else:
        print("Error User do not exists")
        return "Fail", "Error Email do not exists"


while True:
    data = clientsocket.recv(4096)
    if data.__len__() != 0:
        print("*" * 100)
        print(f"The ip:{address} has sent a command!")
        status, response = command(data)
        msg = pickle.dumps({
            "Status": status,
            "Response": response
        })
        print(f"Server responsed to ip:{address} with status:{status}")
        print("*" * 100)
        msg = bytes(f'{len(msg):<{HEADER_LENGTH}}', 'utf-8') + msg
        clientsocket.send(msg)
