#!/usr/bin/env python3

import socket
import pyDH
import rsa

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
ATTESTER_HOST = HOST
#'192.168.0.219'
PORT_SERVER = 65432 
PORT_CLIENT = 65433
PORT_EPCA = 65434
PORT_VERIFIER = 65435
PORT_ATTESTER = 65436

#Generate Keys:

#Client
client_sym_int = 0 # Client's symmetric key(AES). This value is updated after client starts and sends its public key to EPCA

server_public_n = 0
server_public_e = 0

verifier_public_n = 0
verifier_public_e = 0

attester_public_n = 0
attester_public_e = 0


while(True):
    data_cumulative = ""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_to_epca:
        s_to_epca.bind((HOST, PORT_EPCA))
        s_to_epca.listen()
        conn, addr = s_to_epca.accept()
        with conn:
            while True:
                data = conn.recv(1024)
                data = data.decode()
                data_cumulative += data
                if not data:
                    break
            fields = data_cumulative.split("|")
            req_type = fields[0].split(":",1)[1]

            if req_type == "VREP02":
                # Receive request from Verifier
                # Next -> EPVR01
                REQ = "EPVR01"
                Cert = "Certificate"
                A = "A"
                I = "I"
                E = "E"
                data_epvr = 'REQ:' + REQ + '|Cert:' + Cert + '|A:' + A + '|I:' + I + '|E:' + E
                data_epvr = data_epvr.encode()
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as epvr:
                    epvr.connect((HOST, PORT_VERIFIER))
                    epvr.sendall(data_epvr)
            elif req_type == "CLEP01": #Client sends its int. sym. key
                # Update the client's int. sym. key
                client_sym_int = fields[1].split(":",1)[1]
                # Next -> EPCL01
                # Send Ks to client
                REQ = "EPCL01"
                Ks_n = server_public_n
                Ks_e = server_public_e
                print("EPCL01: SENT SERVER'S PUBLIC KEY TO CLIENT\n")
                print("\n---------------------------------------------------------\n")
                data_epcl = 'REQ:' + REQ + '|Ks_n:' + str(Ks_n) + '|Ks_e:' + str(Ks_e)
                data_epcl = data_epcl.encode()
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as epcl:
                    epcl.connect((HOST, PORT_CLIENT))
                    epcl.sendall(data_epcl)
                    
                # Next -> EPVR02
                REQ = "EPVR02"
                Ks_n = server_public_n
                Ks_e = server_public_e
                Ka_n = attester_public_n
                Ka_e = attester_public_e
                #attester public key
                print("EPVR02: SENT SERVER AND ATTESTER'S PUBLIC KEY TO VERIFIER\n")
                print("\n---------------------------------------------------------\n")
                data_epvr = 'REQ:' + REQ + '|Ks_n:' + str(Ks_n) + '|Ks_e:' + str(Ks_e) + '|Ka_n:' + str(Ka_n) + '|Ka_e:' + str(Ka_e)
                data_epvr = data_epvr.encode()
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as epvr:
                    epvr.connect((HOST, PORT_VERIFIER))
                    epvr.sendall(data_epvr)
                    
            elif req_type == "SVEP01": #Server sends its public key
                # Update the client's public key
                server_public_n = fields[1].split(":",1)[1]
                server_public_e = fields[2].split(":",1)[1]
                print("SVEP01: RECEIVED SERVER'S PUBLIC KEY\n")
                print(rsa.key.PublicKey(int(server_public_n), int(server_public_e)))
                print("\n---------------------------------------------------------\n")
                # Next -> EPSV01
                # Send Kv to server
                print("EPSV01: SENT VERIFIER'S PUBLIC KEY TO SERVER\n")
                print("\n---------------------------------------------------------\n")
                REQ = "EPSV01"
                Kv_n = verifier_public_n
                Kv_e = verifier_public_e
                data_epsv = 'REQ:' + REQ + '|Kv_n:' + str(Kv_n) + '|Kv_e:' + str(Kv_e)
                data_epsv = data_epsv.encode()
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as epsv:
                    epsv.connect((HOST, PORT_SERVER))
                    epsv.sendall(data_epsv)

                # Send Kv to attester
                print("EPAT01: SENT VERIFIER'S PUBLIC KEY TO ATTESTER")
                print("\n---------------------------------------------------------\n")
                REQ = "EPAT01"
                data_epat = 'REQ:' + REQ + '|Kv_n:' + str(Kv_n) + '|Kv_e:' + str(Kv_e)
                data_epat = data_epat.encode()
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as epat:
                    epat.connect((ATTESTER_HOST, PORT_ATTESTER))
                    epat.sendall(data_epat)
                
            elif req_type == "VREP01":
                #Update the verifier's public key
                print("VREP01: RECEIVED VERIFIER'S PUBLIC KEY\n")
                verifier_public_n = fields[1].split(":",1)[1]
                verifier_public_e = fields[2].split(":",1)[1]
                print(rsa.key.PublicKey(int(verifier_public_n), int(verifier_public_e)))
                print("\n---------------------------------------------------------\n")

            elif req_type == "ATEP01":
                attester_public_n = fields[1].split(":",1)[1]
                attester_public_e = fields[2].split(":",1)[1]
                print("\nATEP01: RECEIVED ATTESTER'S PUBLIC KEY\n")
                print(rsa.key.PublicKey(int(attester_public_n), int(attester_public_e)))
                print("\n---------------------------------------------------------\n")
