import socket
import sys
from Crypto.Cipher import AES
import random
import time 

alice_as_key = 'Alice0000As11111'
alice_as_key = alice_as_key.encode('utf-8')
alice_tgs_key = ' '
alice_bob_session_key = ' '
alice_nonce = random.getrandbits(64)

as_port = 1019
tgs_port = 2013
bob_port = 2077

print('Establishing connection with as server......')

s1 = socket.socket()
s1.connect(('127.0.0.1',as_port))

s1.send('Alice'.encode('utf-8'))
s1.recv(50).decode('utf-8')

alice_as_nonce = s1.recv(49)
s1.send('ACK'.encode('utf-8'))
encrypted_alice_tgs_key =  s1.recv(49)
s1.send('ACK'.encode('utf-8'))

d_cipher = AES.new(alice_as_key, AES.MODE_EAX, alice_as_nonce)
alice_tgs_key = d_cipher.decrypt(encrypted_alice_tgs_key).decode('utf-8')
print('recieved alice-tgs key' , alice_tgs_key)
# print(alice_as_nonce)
# print(encrypted_alice_tgs_key)
as_tgs_nonce = s1.recv(49)
s1.send('ACK'.encode('utf-8'))
# print(as_tgs_nonce)
encrypted_as_tgs_ticket = s1.recv(55)
s1.send('ACK'.encode('utf-8'))
# print(encrypted_as_tgs_ticket)
as_tgs_ticket = d_cipher.decrypt(encrypted_as_tgs_ticket)
print('recieved as-tgs ticket encrypted with as-tgs key',as_tgs_ticket)
alice_tgs_cipher = AES.new(alice_tgs_key.encode('utf-8'),AES.MODE_EAX)
timestamp = time.time()
print('Sending timestamp \'' + str(timestamp) + '\' to tgs server')
encrypted_timestamp = alice_tgs_cipher.encrypt(str(timestamp).encode('utf-8'))

s2 = socket.socket()
s2.connect(('127.0.0.1',tgs_port))

s2.send('Bob'.encode('utf-8'))
s2.recv(50)

s2.send(as_tgs_nonce)
s2.recv(50)

s2.send(as_tgs_ticket)
s2.recv(50)

s2.send(alice_tgs_cipher.nonce)
s2.recv(50)
print('sending timestamp \'' + str(timestamp) + '\' as nonce to tgs server')
s2.send(encrypted_timestamp)
response = s2.recv(70).decode('utf-8') 
if response == 'request failed' : 
    exit(0)
else :
    print('TGS server : ' + response)
    s2.send('ACK'.encode('utf-8'))
    alice_tgs_nonce = s2.recv(55)
    s2.send('ACK'.encode('utf-8'))
    alice_packet = s2.recv(55)
    s2.send('ACK'.encode('utf-8'))
    alice_tgs_d_crypt = AES.new(alice_tgs_key.encode('utf-8'), AES.MODE_EAX, alice_tgs_nonce)
    alice_packet = alice_tgs_d_crypt.decrypt(alice_packet).decode('utf-8')
    alice_bob_session_key = alice_packet.split(' ')[1]
    print('Recieved Session Key from TGS server: '+ alice_bob_session_key)
    bob_tgs_nonce = s2.recv(55)
    s2.send('ACK'.encode('utf-8'))
    bob_packet = s2.recv(60)
    s2.send('ACK'.encode('utf-8'))

    s3 = socket.socket()
    s3.connect(('127.0.0.1',bob_port))
    
    s3.send(bob_tgs_nonce)
    s3.recv(50)
    s3.send(bob_packet)
    s3.recv(50)
    
    alice_bob_cipher = AES.new(alice_bob_session_key.encode('utf-8'), AES.MODE_EAX)
    timestamp = time.time()
    print('Sending Timestamp to Bob : \'' + str(timestamp) + '\' as a nonce to Bob')
    encrypted_timestamp = alice_bob_cipher.encrypt(str(timestamp).encode('utf-8'))

    s3.send(alice_bob_cipher.nonce)
    s3.recv(50)
    s3.send(encrypted_timestamp)
    s3.recv(50)

    
    alice_bob_cipher = AES.new(alice_bob_session_key.encode('utf-8'), AES.MODE_EAX, alice_bob_cipher.nonce)

    encrypted_timestamp = s3.recv(55)
    recieved_timestamp = alice_bob_cipher.decrypt(encrypted_timestamp).decode('utf-8')
    if timestamp - float(recieved_timestamp) == 1 : 
        print('recieved nonce(timestamp-1) \'' + recieved_timestamp + '\' guarentees that the connection with bob is secured safely!!')
    else : 
        print('Connection with Bob failed!!') 