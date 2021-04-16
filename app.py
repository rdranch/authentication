# Author: Russell Dranch
# RIT CSEC472 Group 12
# Handles (10)

import socket, json, base64

addr = ""
port = 80

key = "qwerty1234"

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #Create CLIENT socket object
listener.bind((addr, port))	# Bind to port
listener.listen(3)	
c, l_addr = listener.accept()	# Establish connection with client

msg = c.recv(1024).decode()
msg_s = msg.replace("'", "\"")

try:
	msg_s = json.loads(msg_s)
	token = msg_s.get("token")
	decrypted = decode(key, token)
	print(decrypted)
except:
	print("Failed")
