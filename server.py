#!/usr/bin/env python3

import pyDH
import rsa
import socket
import pickle
from Crypto.Cipher import AES
import hashlib

HOST            = '127.0.0.1'
ATTESTER_HOST = HOST
#'192.168.0.219'
PORT_SERVER     = 65432 
PORT_CLIENT     = 65433
PORT_EPCA       = 65434
PORT_VERIFIER   = 65435
PORT_ATTESTER   = 65436

# Generate RSA public private key pair and send pubic key to EPCA. This will be Ks
(server_pub, server_priv) = rsa.newkeys(1024)

# Verifier's public key
verifier_public_e = 0
verifier_public_n = 0

client_sym = b''

# As soon as the server starts, it sends its intermediate symmetric key(for DH) and public key(for RSA) to EPCA
# SVEP01
REQ = "SVEP01" 
Ks_n = server_pub['n']
Ks_e = server_pub['e']
data_svep = 'REQ:' + REQ + '|Ks_n:' + str(Ks_n) + '|Ks_e:' + str(Ks_e)
data_svep = data_svep.encode()
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_to_epca:
    s_to_epca.connect((HOST, PORT_EPCA))
    s_to_epca.sendall(data_svep)
    print("SVEP01: SENT PUBLIC KEY TO EPCA\n")
    print("\n---------------------------------------------------------\n")

# Wait to receive verifier's public key from EPCA   
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_to_server:
    data_cumulative = ""
    s_to_server.bind((HOST, PORT_SERVER))
    s_to_server.listen()
    conn, addr = s_to_server.accept()
    with conn:
        while True:
            data = conn.recv(1024)
            data = data.decode()
            data_cumulative += data
            if not data:
                break
        fields = data_cumulative.split("|")
        req_type = fields[0].split(":",1)[1]
        if req_type == "EPSV01":
            verifier_public_n = int(fields[1].split(":",1)[1])
            verifier_public_e = int(fields[2].split(":",1)[1])
            print("EPSV01: RECEIVED VERIFIER'S PUBLIC KEY FROM EPCA\n")
            print("\n---------------------------------------------------------\n")

while(True):
    data_cumulative = b''
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_to_server:
        s_to_server.bind((HOST, PORT_SERVER))
        s_to_server.listen()
        conn, addr = s_to_server.accept()
        with conn:
            while True:
                data = conn.recv(1024)
                if data == b'':
                    break
                #data = data.decode()
                data_cumulative += data
                                
            fields = data_cumulative.split(b'|~|')
            data_cumulative = fields[1]
            req_type = fields[0].split(b':',1)[1]
            if req_type == b'CLSV01':
                # Extract {R, A, K}Ks
                # Didn't decode rsa.decrypt().decode()
                decrypted = rsa.decrypt(data_cumulative, server_priv)
                print("CLSV01: RECEIVED AND DECRYPTED CLIENT'S MESSAGE TO GET ITS SYMMETRIC KEY\n")
                print("\n---------------------------------------------------------\n")
                fields = decrypted.split(b'|')                
                R = fields[1].split(b':',1)[1]
                A = fields[2].split(b':',1)[1]
                K = fields[3].split(b':',1)[1]
                client_sym = K
                # Next -> SVVR01
                REQ = "SVVR01"
                S = "S"
                R = "Nv"
                A = "J"
                Ns = "V"
                data_svvr = 'REQ:' + REQ + '|S:' + S + '|R:' + R + '|A' + A + '|Ns:' + Ns
                data_svvr = data_svvr.encode('utf8')
                data_svvr = rsa.encrypt(data_svvr, rsa.PublicKey(verifier_public_n, verifier_public_e))
                data_svvr = b'REQ:SVVR01|~|' + data_svvr
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as svvr:
                    svvr.connect((HOST, PORT_VERIFIER))
                    svvr.sendall(data_svvr)
                    print("SVVR01: FORWARDED CLIENT'S MESSAGE TO VERIFIER. ULTIMATE DESTINATION - ATTESTER\n")
                    print("\n---------------------------------------------------------\n")
                    
            elif req_type == b'VRSV01':
                # Extract {Nv, J, V, Ns, M}Ks
                # Next -> SVCL01
                print("VRSV01: RECEIVED ATTESTATION REQUEST FROM CLIENT\n")
                print("\n---------------------------------------------------------\n")
                cipher = AES.new(client_sym, AES.MODE_EAX)
                decrypted = rsa.decrypt(data_cumulative, server_priv).decode()
                fields = decrypted.split("|")
                REQ = "SVCL01"
                Nv = "Nv"
                J = "J"
                V = "V"
                M = "M"
                data_svcl = 'REQ:' + REQ + '|Nv:' + Nv + '|J:' + J + '|V:' + V + '|M:' + M
                data_svcl = data_svcl.encode('utf8')
                ciphertext, tag = cipher.encrypt_and_digest(data_svcl)
                # Nonce is also included in the message
                data_svcl = b'REQ:SVCL01|~|' + cipher.nonce + b'|' + ciphertext
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as svcl:
                    svcl.connect((HOST, PORT_CLIENT))
                    svcl.sendall(data_svcl)
                    print("SVCL01: FORWARD ATTESTATION REQUEST TO CLIENT. ULTIMATE DESTINATION - ATTESTER\n")
                    print("\n---------------------------------------------------------\n")

            elif req_type == b'CLSV02':
                # Extract B
                # Next -> SVVR02
                print("CLSV02: RECEIVE ATTESTATION RESPONSE FROM CLIENT\n")
                print("\n---------------------------------------------------------\n")
                REQ = b'SVVR02'
                B = data_cumulative
                data_svvr = b'REQ:' + REQ + b'|~|' + B
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as svvr:
                    svvr.connect((HOST, PORT_VERIFIER))
                    svvr.sendall(data_svvr)
                    print("SVVR02: FORWARD ATTESTATION RESPONSE TO VERIFIER\n")
                    print("\n---------------------------------------------------------\n")
            elif req_type == "VRSV02":
                # Extract {valid, Ns, K'}Ks
                # Next SVCL02
                REQ = "SVCL02"
                data_ = "data"
                D = "D"
                data_svcl = 'REQ:' + REQ + '|Data:' + data_ + '|D:' + D
                data_svcl = data_svcl.encode()
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as svcl:
                    svcl.connect((HOST, PORT_CLIENT))
                    svcl.sendall(data_svcl)
            else:
                print("Error in parsing header")   
