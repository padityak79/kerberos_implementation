import socket
import sys
from Crypto.Cipher import AES


alice_as_key = 'Alice0000As11111'
alice_tgs_key = 'Alice0000Tgs1111'
as_tgs_key = 'As000000Tgs11111'
alice_as_key = alice_as_key.encode('utf-8')
# alice_tgs_key = alice_tgs_key.encode('utf-8')
as_tgs_key = as_tgs_key.encode('utf-8')

as_port = 1019

s1 = socket.socket()
s1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s1.bind(('127.0.0.1',as_port))
s1.listen()

print('Socket is listening')

client, addr = s1.accept()

# print(client)
print('Connected to : ', client.recv(100))
client.send('ACK connection request reieved'.encode('utf-8'))

as_tgs_ticket = 'Alice ' + alice_tgs_key
as_tgs_ticket = as_tgs_ticket.encode('utf-8')
# print(as_tgs_ticket)
as_tgs_cipher = AES.new(as_tgs_key, AES.MODE_EAX)

as_tgs_ticket = as_tgs_cipher.encrypt(as_tgs_ticket)
print(as_tgs_ticket)
print(as_tgs_cipher.nonce)


alice_as_cipher = AES.new(alice_as_key,AES.MODE_EAX)


alice_tgs_key = alice_tgs_key.encode('utf-8')
# print(alice_tgs_key)
encrypted_alice_tgs_key = alice_as_cipher.encrypt(alice_tgs_key)
# print(alice_as_cipher.nonce)


encrypted_as_tgs_ticket = alice_as_cipher.encrypt(as_tgs_ticket)
# print(encrypted_as_tgs_ticket)

client.send(alice_as_cipher.nonce)
client.recv(50)
client.send(encrypted_alice_tgs_key)
client.recv(50)

client.send(as_tgs_cipher.nonce)
client.recv(50)
client.send(encrypted_as_tgs_ticket)
client.recv(50)