import sqlite3
from ElgamalEcc.Curve import secp256k1
from Signature.Key import gen_keypair
db_name='emailapp.db'



def create_tables():
    # creates the tables database.
    user_query = """CREATE TABLE users (
     email text PRIMARY KEY,
     password text NOT NULL,
     privateKey text NOT NULL,
     publicKey text NOT NULL)"""

    email_query = """CREATE TABLE emails (
         fromsend text NOT NULL,
         tosend text NOT NULL,
         cypherMessage text NOT NULL,
         c1 text NOT NULL,
         c2 text NOT NULL,
         iv text NOT NULL,
         date text NOT NULL)"""
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute(user_query)
    conn.commit()
    c.execute(email_query)
    conn.commit()
    print('Tables Created')
    conn.close()

def fill_database():
    # Insert users to the database.
    pri_key, pub_key = gen_keypair(secp256k1)
    query = "INSERT INTO users VALUES ('{}','{}','{}','{}')".format("rafa@gmail.com", "rafa", pri_key, pub_key)
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute(query)
    conn.commit()

    pri_key, pub_key = gen_keypair(secp256k1)
    query = "INSERT INTO users VALUES ('{}','{}','{}','{}')".format("roman@gmail.com", "roman", pri_key, pub_key)
    c.execute(query)
    conn.commit()

    pri_key, pub_key = gen_keypair(secp256k1)
    query = "INSERT INTO users VALUES ('{}','{}','{}','{}')".format("kfir@gmail.com", "kfir", pri_key, pub_key)
    c.execute(query)
    conn.commit()

    pri_key, pub_key = gen_keypair(secp256k1)
    query = "INSERT INTO users VALUES ('{}','{}','{}','{}')".format("shoval@gmail.com", "shoval", pri_key, pub_key)
    c.execute(query)
    conn.commit()
    print('User table filles')
    conn.close()


def checkdb():
    query = "SELECT * FROM users"
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute(query)
    conn.commit()
    result = c.fetchall()
    #print(result)
    print("DB was checked is ready for use")
    conn.close()

def checkemails():
    query = "SELECT * FROM emails"
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute(query)
    conn.commit()
    result = c.fetchall()
    print(result)
    conn.close()

def login(email):
    try:
        query = "SELECT * FROM users WHERE email='{}'".format(email)
        conn = sqlite3.connect(db_name)
        c = conn.cursor()
        c.execute(query)
        conn.commit()
        result = c.fetchall()
    except sqlite3.Error as error:
        print("Failed to insert data into sqlite table", error)
    finally:
        if (conn):
            conn.close()
            print("The SQLite connection is closed")
            return result

def get_key(email):
    try:
        query = "SELECT * FROM users WHERE email='{}'".format(email)
        conn = sqlite3.connect(db_name)
        c = conn.cursor()
        c.execute(query)
        conn.commit()
        result = c.fetchall()
    except sqlite3.Error as error:
        print("Failed to insert data into sqlite table", error)
    finally:
        if (conn):
            conn.close()
            print("The SQLite connection is closed")
            return result

def get_private_key(email):
    try:
        query = "SELECT * FROM users WHERE email='{}'".format(email)
        conn = sqlite3.connect(db_name)
        c = conn.cursor()
        c.execute(query)
        conn.commit()
        result = c.fetchall()
    except sqlite3.Error as error:
        print("Failed to insert data into sqlite table", error)
    finally:
        if (conn):
            conn.close()
            print("The SQLite connection is closed")
            return result

def send_email(email_object):
    try:
        query = "INSERT INTO emails VALUES ('{}','{}','{}','{}','{}','{}','{}')".format(email_object['source'], email_object['to'], email_object['cypherMessage'], email_object['c1'], email_object['c2'], email_object['iv'], email_object['date'])
        conn = sqlite3.connect(db_name)
        c = conn.cursor()
        c.execute(query)
        conn.commit()
        result= "Email sent to: "+email_object['to']
    except sqlite3.Error as error:
        print("Failed to insert data into sqlite table", error)
        result = 'None'
    finally:
        if (conn):
            conn.close()
            print("The SQLite connection is closed")
        return result

def get_inbox(email):
    try:
        query = "SELECT * FROM emails WHERE tosend='{}'".format(email)
        conn = sqlite3.connect(db_name)
        c = conn.cursor()
        c.execute(query)
        conn.commit()
        result = c.fetchall()
    except sqlite3.Error as error:
        print("Failed to insert data into sqlite table", error)
        result = 'None'
    finally:
        if (conn):
            conn.close()
            print("The SQLite connection is closed")
            return result

try:
    print(f'Checking if {db_name} exists or not...')
    conn = sqlite3.connect(db_name, uri=True)
    print(f'Database exists. Succesfully connected to {db_name}')
    conn.close()
    checkdb()
except sqlite3.OperationalError as err:
    print('Database does not exist, creating now...')
    create_tables()
    fill_database()


