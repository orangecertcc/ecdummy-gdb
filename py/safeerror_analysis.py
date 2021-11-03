#!/usr/bin/env python3

from base64 import b64decode as b64d
from hashlib import sha256
import argparse
import os
from ec import *

def pubkey_to_point(curve, pubkey_filename):
    '''convert the public key file of the signer into two integers (works for secp256k1)'''

    text = open(pubkey_filename, 'r').read().split('\n')
    pubkey = b64d(text[1] + text[2])
    xx, yy = int.from_bytes(pubkey[-64:-32], 'big'), int.from_bytes(pubkey[-32:], 'big')
    return curve.field(xx), curve.field(yy)


def sig_to_integer(sig_filename):
    '''convert the raw signature to a list of couple of integers (r,s)'''

    list_sig = []
    raw = open(sig_filename, 'rb').read()
    i = 0
    while i < len(raw):
        length = raw[i + 1]
        sig = raw[i + 2:i + 2 + length]
        i += (2 + length)
        rlen = sig[1]
        r = int.from_bytes(sig[2:2 + rlen], 'big')
        s = int.from_bytes(sig[4 + rlen:], 'big')
        list_sig.append((r,s))
        
    return list_sig


def msg_to_integer(msg_filename):
    '''convert the signed file to an integer with SHA-256'''
    return int.from_bytes(sha256(open(msg_filename, 'rb').read()).digest(), 'big')


def batch_verify(curve, pubkey, msg_filename, sig_filename):
    '''returns list of valid signatures stored in the file `sig_filename`'''

    list_sig = sig_to_integer(sig_filename)
    msg = msg_to_integer(msg_filename)

    valid_sig = []
    for i,sig in enumerate(list_sig):
        valid, Q = ecdsa_verify(curve, pubkey, msg, sig)
        if valid:
            print(f'Signature {i+1}/{len(list_sig)} valid')
            valid_sig.append(sig)

    return valid_sig


def launch_attack(curve, sig_filename, msg_filename, pubkey_filename, fname, lsb, padding, ell):
    pubkey = pubkey_to_point(curve, pubkey_filename)
    
    msg = msg_to_integer(msg_filename)
    valid_sig = batch_verify(curve, pubkey, msg_filename, sig_filename)

    print(f'Number of valid signatures: {len(valid_sig)}')
    
    Ui, Vi, Li = [], [], []
    for sig in valid_sig:
        
        r, s = sig
        if lsb:
            tmp = invmod(s*2**ell, curve.order)
            if padding:
                B1 = 2**curve.order.bit_length() >> ell
                B2 = (2**curve.order.bit_length() + curve.order) >> ell
            else:
                B1 = 0
                B2 = curve.order >> ell
        else:
            # no padding
            tmp = invmod(s, curve.order)
            B1 = 0
            B2 = 2**(curve.order.bit_length() - ell)


        u = r*tmp % curve.order
        v = msg*tmp % curve.order
        C = (B1 + B2)//2
        LL = curve.order//(B2 - B1)
        vv = C - v
        
        Ui.append(u)
        Vi.append(vv)
        Li.append(LL)

    f = open(fname, 'w')
    # We only keep the curve name and the public key
    f.write(f'{curve.name},{pubkey[0].hex()},{pubkey[1].hex()}\n')
    for u,v,L in zip(Ui,Vi,Li):
        f.write(f'{u:x},{v:x},{L}\n')
    f.close()
        
    print(f'The results of the analysis are stored in {fname}')
    print(f'Run the command "python3 solve_hnp.py {fname}" to find the private key')
    

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Safe-Error analysis')

    parser.add_argument('--curve', action='store', dest='curvename', type=str,
                        help='name of the curve (secp256r1 or secp256k1 for example)', required=True)
    parser.add_argument('--pubkey', action='store', dest='pubkey_filename', type=str,
                        help='/path/to/publickey', required=True)

    parser.add_argument('--sig', action='store', dest='sig_filename', type=str,
                        help='/path/to/signatures_file', required=True)

    parser.add_argument('--msg', action='store', dest='msg_filename', type=str,
                        help='/path/to/message', required=True)

    parser.add_argument('--lsb', action='store_true')
    parser.add_argument('--msb', action='store_true')
    parser.add_argument('--padding', action='store_true')
    parser.add_argument('--ell', action='store', dest='ell', type=int,
                        help='number of bits set to 0', required=True)

    parser.add_argument('--out', action='store', dest='fname', type=str,
                        help='file name to store the results of analysis', required=True)
    
    args = parser.parse_args()

    if args.padding and args.msb:
        print('Argument `--padding` will be ignored')

    if (not args.lsb and not args.msb) or (args.lsb and args.msb):
        print('Please provide either `--lsb` or `--msb` argument but not both')
    else:
        curve = CurveJac(CURVES[args.curvename])
        lsb = args.lsb
        launch_attack(curve, args.sig_filename, args.msg_filename, args.pubkey_filename, args.fname, lsb, args.padding, args.ell)

