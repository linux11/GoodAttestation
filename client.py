#!/usr/bin/env python3
import json
import socket
import pyDH
import rsa
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import hashlib

HOST = '127.0.0.1'
ATTESTER_HOST = HOST
#'192.168.0.219'
CLIENT_NAME = 'DORR'

PORT_SERVER = 65432 
PORT_CLIENT = 65433
PORT_EPCA = 65434
PORT_VERIFIER = 65435
PORT_ATTESTER = 65436

server_public_n = 0
server_public_e = 0

d1 = pyDH.DiffieHellman()
# This is symmetric key K(AES)
client_sym = get_random_bytes(16)

#As soon as the client starts, it sends its intermediate symmetric key to EPCA
# CLEP01
#This is unnecessary, because K is sent to server in message (CLSV01)
REQ = "CLEP01" 
K_sym = client_sym
data_clep = 'REQ:' + REQ + '|K_sym:' + str(K_sym)
data_clep = data_clep.encode()
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_to_epca:
    s_to_epca.connect((HOST, PORT_EPCA))
    s_to_epca.sendall(data_clep)
    print("CLEP01: SENT CLIENT'S PUBLIC KEY TO EPCA\n")
    print("\n---------------------------------------------------------\n")
    

# Wait until data from EPCA is received, and subsequent CLSV is done. This is done in string format
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_from_client:
    data_cumulative = ""
    s_from_client.bind((HOST, PORT_CLIENT))
    s_from_client.listen()
    conn, addr = s_from_client.accept()
    with conn:
        while True:
            data = conn.recv(1024)
            data = data.decode()
            data_cumulative += data
            if not data:
                break
        fields = data_cumulative.split("|")
        req_type = fields[0].split(":",1)[1]
        if req_type == "EPCL01":
            server_public_n = int(fields[1].split(":",1)[1])
            server_public_e = int(fields[2].split(":",1)[1])

            # CLSV01
            REQ = b'CLSV01'
            R = b'Resource list' #List of resources client can verify
            A = b'AT3456' #Attester ID. This is unique to each client and used to identify client
            K = client_sym #Symmetric Key
            data_clsv = b'REQ:' + REQ + b'|R:' + R + b'|A:'+ A + b'|K:' + K
            data_clsv = rsa.encrypt(data_clsv, rsa.PublicKey(server_public_n, server_public_e))
            data_clsv = b'REQ:CLSV01|~|' + data_clsv
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_to_server:
                s_to_server.connect((HOST, PORT_SERVER))
                s_to_server.sendall(data_clsv)
                print("EPCL01: RECEIVED SERVERS'S PUBLIC KEY FROM EPCA\n")
                print("\n---------------------------------------------------------\n")
                print("CLSV01: SENT CLIENT'S SYMMETRIC KEY AND RESOURCE PARAMETERS TO SERVER\n")
                print(client_sym)
                print("\n---------------------------------------------------------\n")
# Encrypted data is handled here
while(True):
    data_cumulative = b''
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_to_client:
        s_to_client.bind((HOST, PORT_CLIENT))
        s_to_client.listen()
        conn, addr = s_to_client.accept()
        with conn:
            while True:
                data = conn.recv(1024)
                if data == b'':
                    break
                data_cumulative += data
            fields = data_cumulative.split(b'|~|')
            data_cumulative = fields[1]
            req_type = fields[0].split(b':',1)[1]

            if req_type == b'SVCL01':
                data_cumulative = fields[1].split(b'|')[1]
                nonce = fields[1].split(b'|')[0]
                # Extract {Nv, J, V and M}K
                cipher = AES.new(client_sym, AES.MODE_EAX)
                cipher = AES.new(client_sym, AES.MODE_EAX, nonce)
                decrypted = cipher.decrypt(data_cumulative)
                # Next -> CLAT01
                print("SVCL01: RECEIVED ATTESTATION REQUEST FROM SERVER BASED ON RESOURCE PARAMETERS\n")
                print("\n---------------------------------------------------------\n")                
                REQ = "CLAT01"
                S = "S"
                Nv = "Nv"
                J = "J"
                V = "V"
                M = "M"
                R = "R"
                data_clat = 'REQ:' + REQ + '|S:' + S + '|Nv:' + Nv + '|J' + J + '|V:' + V + '|M:' + M + '|R:' + R
                data_clat = data_clat.encode()
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as clat:
                    clat.connect((ATTESTER_HOST, PORT_ATTESTER))
                    clat.sendall(data_clat)
                    print("CLAT01: FORWARD ATTESTATION REQUEST TO ATTESTATOR\n")
                    print("\n---------------------------------------------------------\n")
                    
            elif req_type == b'ATCL01':
                # Extract {K', Nv, B}tk(A,A)
                # Next -> CLSV02
                REQ = b'CLSV02'
                B = data_cumulative
                data_clsv = b'REQ:' + REQ + b'|~|' + B
                print("ATCL01: RECEIVE ATTESTATION RESPONSE FROM ATTESTATOR\n")
                print("\n---------------------------------------------------------\n")
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as clsv:
                    clsv.connect((HOST, PORT_SERVER))
                    clsv.sendall(data_clsv)
                    print("CLSV02: FORWARD ATTESTATION RESPONSE TO SERVER\n")
                    print("\n---------------------------------------------------------\n")

            else:
                print("Error in parsing header")    



