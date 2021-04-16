import socket, hashlib, base64, json

addr = "192.168.195.162"  # change this to whatever the IP of the auth server is
port = 80
page = "/token.php"

appserver = "192.168.196.7" # CHANGE THIS TO APPSERVER IP

uname = input("Enter username: ")
passwd = input("Enter password: ")

parameters = "uname=" + uname + "&passwd=" + passwd
basic = base64.b64encode(f"{uname}:{passwd}".encode('utf-8'))
#basic = "dGVzdGNsaWVudDp0ZXN0cGFzcw==" #test fix

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print("Attempting to connect to " + addr + ":" + str(port)) # Debug info
sock.connect((addr, port))  # in case of adding https later, add sock = ssl.wrap_socket(sock)

request = b"POST " + page.encode() + b" HTTP/1.1\r\nHost: " + addr.encode() + b"\r\nAuthorization: Basic " + basic + b"\r\nUser-Agent: curl/7.68.0\r\nAccept: */*\r\nConnection: close\r\nContent-Length: " + str(len(basic) + 1).encode() + b"\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\ngrant_type=client_credentials\r\n"


#Content-Type: application/x-www-form-urlencoded\r\nContent-Length: " + str(len(parameters)).encode() + b"\r\nHost: " + addr.encode() + b"\r\n\r\n" + parameters.encode() + b"\r\n"


def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

sock.send(request)

#r = b""  # recieve data
#while True:
#    data = sock.recv(1024)
#    if not data:
#        break
#    r = r + data

data = sock.recv(2048)
data = data.decode()

try:
    check = json.loads(data)["auth"]
except:
    check = "success"

if check == "fail":
    print("Invalid credentials.")
else:
    #print(data)
    #print("passwd: " + passwd)
    hashed = hashlib.sha256(passwd.encode()).hexdigest() # PART 9
    #print("hased: " + hashed)
    js = decode(hashed, data) # PART 9
    print("js: " + js)
    server.connect((appserver, port))
    server.sendto(js.encode(),(appserver, port)) # PART 10
    #sock.close()
