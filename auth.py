# Author: Russell Dranch
# RIT CSEC472 Group 12

import base64
import hashlib
import json
import socket

addr = ""  # Host that client is connecting to
# print(addr) # DEbug info

port = 80  # Local port that client is connecting to

auth = "192.168.196.56"  # REPLACE WITH OAUTH SERVER IP
port = 80  # OAUTH SERVER PORT

key = "qwerty1234"


def encode(en_key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = en_key[i % len(en_key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


# Decode function for the above encoding
# def decode(key, enc):
#    dec = []
#    enc = base64.urlsafe_b64decode(enc).decode()
#    for i in range(len(enc)):
#        key_c = key[i % len(key)]
#        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
#        dec.append(dec_c)
#    return "".join(dec)


listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create CLIENT socket object
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind((addr, port))  # Bind to port
print("Listening...")  # Debug information
listener.listen(3)

while True:
    c, l_addr = listener.accept()  # Establish connection with client

    print("Successful client-server connection.")  # Debug information

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create OAUTH SERVER socket object
    local = "192.168.195.162"
    msg = c.recvfrom(1024)[0]  # Receive credential data from client (2)
    fix = msg.decode("utf-8").replace(local, auth)  # Debug information

    # print(fix) # Debug information (AUTh request)
    server.connect((auth, port))
    print("Successful authserver-oauthserver connection.")  # debug information
    server.sendto(fix.encode(), (auth, port))  # Sends HTTP request to OAUTH server (3)
    msg_s = server.recvfrom(1024)  # Receive JSON message from OAUTH server (4)
    server.close()
    msg_s = msg_s[0].decode("utf-8")
    #print("OAUTH server response was: \n" + msg_s) # Debug information (OAUTH reply)
    try:
        token = json.loads(msg_s.split("\r\n")[-1])["access_token"]  # Gets the JSON token
    except:
        token = "fail"
    print("TOK: " + token)  # Debug information  - gets the token

    if token != "fail":  # Valid credentials   (5)
        encrypted = encode(key, msg_s)  # Encrypts JSON msg with key (6)
        js = {"auth": "success", "token": encrypted}  # Construct JSON response reply (7)
        #print(msg.split()) # debug info
        enc = msg.decode().split("\r\n")[2].split()[-1]
        #print("enc:" + enc)
        passwd = base64.b64decode(enc.encode()).decode().split(":")[-1] # Obtains JUST the password from credential request (8)
        #print("Passwd: " + passwd) # debug info
        hashed = hashlib.sha256(passwd.encode()).hexdigest()  # SHA256 hashes with client passwd (8)
        #print("Hashed: " + hashed) #     debug info
        encrypt_two = encode(hashed, str(js))  # JSON response encrypted with SHA256 hash of password (8)
        # print("encrypted: " + encrypt_two) # Debug info - dont use
        # listener.send(encrypt_two.encode())
        c.sendto(encrypt_two.encode(), (l_addr[0], port))  # Sends encrypted JSON response to client (8)
    else:  # Returns failed empty token if incorrect creds (4)
        #print("ELsE")
        ret = "{\"auth\": \"fail\", \"token\": \"\"}"  # The invalid JSON request
        c.sendto(ret.encode(), (l_addr[0], port))  # Sends failed JSON request back to client
