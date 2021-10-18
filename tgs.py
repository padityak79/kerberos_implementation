import socket
import sys
from Crypto.Cipher import AES

import time

alice_tgs_key = ''
bob_tgs_key = 'Bob00000Tgs11111'
as_tgs_key = 'As000000Tgs11111'
as_tgs_key = as_tgs_key.encode('utf-8')
alice_bob_session_key = 'Alice000Bob11111'

tgs_port = 2013

s1 = socket.socket()
s1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s1.bind(('127.0.0.1',tgs_port))
s1.listen()

print('Socket is listening')
client,addr = s1.accept()

print('Requested session-key with', client.recv(50).decode('utf-8'))
client.send('ACK'.encode('utf-8'))

as_tgs_nonce = client.recv(55)
client.send('ACK'.encode('utf-8'))

encrypted_as_tgs_ticket = client.recv(55)
client.send('ACK'.encode('utf-8'))

# print(as_tgs_nonce)
# print(encrypted_as_tgs_ticket)

as_tgs_d_crypt = AES.new(as_tgs_key, AES.MODE_EAX, as_tgs_nonce)
alice_tgs_ticket = as_tgs_d_crypt.decrypt(encrypted_as_tgs_ticket).decode('utf-8')

client_name, alice_tgs_key = alice_tgs_ticket.split(' ')
print('Request by :', client_name)
print('recieved ALice-Tgs key \'' + alice_tgs_key + '\' from Alice encrypted with As-Tgs key')

alice_tgs_nonce = client.recv(55)
client.send('ACK'.encode('utf-8'))

encrypted_timestamp = client.recv(55)
alice_tgs_d_crypt = AES.new(alice_tgs_key.encode('utf-8'), AES.MODE_EAX, alice_tgs_nonce)
recieved_timestamp = alice_tgs_d_crypt.decrypt(encrypted_timestamp).decode('utf-8')

print('recieved timestamp \'' + recieved_timestamp + '\' from Alice')

if time.time() - float(recieved_timestamp) > 0.5 : 
    client.send('request failed'.encode('utf-8'))
    client.close()
else :
    client.send('Recognised Alice....Preparing the requested session key'.encode('utf-8'))
    client.recv(50)
    alice_tgs_cipher = AES.new(alice_tgs_key.encode('utf-8'),AES.MODE_EAX)
    alice_packet = 'Bob ' + alice_bob_session_key
    print('sending Alice\'s packet \'' + alice_packet + '\' to Alice')
    alice_packet = alice_packet.encode('utf-8')
    encrypted_alice_packet = alice_tgs_cipher.encrypt(alice_packet)
    client.send(alice_tgs_cipher.nonce)
    client.recv(50)
    client.send(encrypted_alice_packet)
    client.recv(50)

    bob_tgs_cipher = AES.new(bob_tgs_key.encode('utf-8'),AES.MODE_EAX)
    bob_packet = 'Alice ' + alice_bob_session_key
    print('sending Bob\s packet \'' + bob_packet + '\' to Alice')
    bob_packet = bob_packet.encode('utf-8')
    encrypted_bob_packet = bob_tgs_cipher.encrypt(bob_packet)
    client.send(bob_tgs_cipher.nonce)
    client.recv(50)
    client.send(encrypted_bob_packet)
    client.recv(50)

