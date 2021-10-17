import socket
import sys
from Crypto.Cipher import AES

import random

bob_tgs_key = 'Bob00000Tgs11111'
alice_bob_session_key = ''
bob_nonce = random.getrandbits(64)

bob_port = 2077

s1 = socket.socket()
s1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s1.bind(('127.0.0.1',bob_port))
s1.listen()
print('Socket is listening')
client, addr = s1.accept()

print('Connected to address ' + addr[0] + ':' + str(addr[1]))

bob_tgs_nonce = client.recv(55)
client.send('ACK'.encode('utf-8'))

bob_packet = client.recv(55)
client.send('ACK'.encode('utf-8'))

bob_tgs_d_crypt = AES.new(bob_tgs_key.encode('utf-8'), AES.MODE_EAX, bob_tgs_nonce)
bob_packet = bob_tgs_d_crypt.decrypt(bob_packet).decode('utf-8')

client_name, alice_bob_session_key = bob_packet.split(' ')

alice_bob_nonce = client.recv(55)
client.send('ACK'.encode('utf-8'))

encrypted_timestamp = client.recv(55)
client.send('ACK'.encode('utf-8'))

alice_bob_d_crypt = AES.new(alice_bob_session_key.encode('utf-8'), AES.MODE_EAX, alice_bob_nonce)
recieved_timestamp = alice_bob_d_crypt.decrypt(encrypted_timestamp).decode('utf-8')
recieved_timestamp = float(recieved_timestamp)

recieved_timestamp -= 1.0
alice_bob_cipher = AES.new(alice_bob_session_key.encode('utf-8'), AES.MODE_EAX, alice_bob_nonce)
encrypted_timestamp = alice_bob_cipher.encrypt(str(recieved_timestamp).encode('utf-8'))

client.send(encrypted_timestamp)
client.recv(50)