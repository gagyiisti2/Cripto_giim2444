#!/usr/bin/env python3 -tt
"""
File: crypto.py
---------------
Assignment 1: Cryptography
Course: CS 41
Name: <YOUR NAME>
SUNet: <SUNet ID>

Replace this with a description of the program.
"""
import utils

# Caesar Cipher

def encrypt_caesar(plaintext):
    if not isinstance(plaintext, str):
        raise TypeError("plaintext must be a string")
    ciphertext = ""
    ordA = ord('A')
    for c in plaintext:
        o = ord(c) - ordA
        if o in range(0,26):
            o = ((o + 3) % 26) + ordA
            c = chr(o)
        ciphertext += c
    return ciphertext

def decrypt_caesar(ciphertext):
    if not isinstance(ciphertext, str):
        raise TypeError("plaintext must be a string")
    plaintext = ""
    ordA = ord('A')
    for c in ciphertext:
        o = ord(c) - ordA
        if o in range(0,26):
            o = ((o - 3) % 26) + ordA
            c = chr(o)
        plaintext += c
    return plaintext

# Ceasar in bytes
def encrypt_ceasar_bytes(data):
    return bytes((b + 3) % 256 for b in data)

def decrypt_ceasar_bytes(encrypted_data):
    return bytes((b - 3) % 256 for b in encrypted_data)     


# Vigenere Cipher

def encrypt_vigenere(plaintext, keyword):
    if not isinstance(plaintext, str):
        raise TypeError("plaintext must be a string")
    if not keyword or not keyword.isalpha():
        raise ValueError("keyword must be a non-empty string of letters")
    ciphertext = ""
    ordA = ord('A')
    for i in range(0, len(plaintext)):
        o = ord(plaintext[i]) - ordA
        key = ord(keyword[i % len(keyword)]) - ordA
        if o in range(0,26) and key in range(0, 26):
            o = ((o + key) % 26) + ordA
            c = chr(o)
        ciphertext += c
    return ciphertext


def decrypt_vigenere(ciphertext, keyword):
    if not isinstance(ciphertext, str):
        raise TypeError("plaintext must be a string")
    if not keyword or not keyword.isalpha():
        raise ValueError("keyword must be a non-empty string of letters")
    plaintext = ""
    ordA = ord('A')
    for i in range(0, len(ciphertext)):
        o = ord(ciphertext[i]) - ordA
        key = ord(keyword[i % len(keyword)]) - ordA
        if o in range(0,26) and key in range(0, 26):
            o = ((o - key) % 26) + ordA
            c = chr(o)
        plaintext += c
    return plaintext


# Merkle-Hellman Knapsack Cryptosystem

def generate_private_key(n=8):
    """Generate a private key for use in the Merkle-Hellman Knapsack Cryptosystem.

    Following the instructions in the handout, construct the private key components
    of the MH Cryptosystem. This consistutes 3 tasks:

    1. Build a superincreasing sequence `w` of length n
        (Note: you can check if a sequence is superincreasing with `utils.is_superincreasing(seq)`)
    2. Choose some integer `q` greater than the sum of all elements in `w`
    3. Discover an integer `r` between 2 and q that is coprime to `q` (you can use utils.coprime)

    You'll need to use the random module for this function, which has been imported already

    Somehow, you'll have to return all of these values out of this function! Can we do that in Python?!

    @param n bitsize of message to send (default 8)
    @type n int

    @return 3-tuple `(w, q, r)`, with `w` a n-tuple, and q and r ints.
    """
    raise NotImplementedError  # Your implementation here

def create_public_key(private_key):
    """Create a public key corresponding to the given private key.

    To accomplish this, you only need to build and return `beta` as described in the handout.

        beta = (b_1, b_2, ..., b_n) where b_i = r × w_i mod q

    Hint: this can be written in one line using a list comprehension

    @param private_key The private key
    @type private_key 3-tuple `(w, q, r)`, with `w` a n-tuple, and q and r ints.

    @return n-tuple public key
    """
    raise NotImplementedError  # Your implementation here


def encrypt_mh(message, public_key):
    """Encrypt an outgoing message using a public key.

    1. Separate the message into chunks the size of the public key (in our case, fixed at 8)
    2. For each byte, determine the 8 bits (the `a_i`s) using `utils.byte_to_bits`
    3. Encrypt the 8 message bits by computing
         c = sum of a_i * b_i for i = 1 to n
    4. Return a list of the encrypted ciphertexts for each chunk in the message

    Hint: think about using `zip` at some point

    @param message The message to be encrypted
    @type message bytes
    @param public_key The public key of the desired recipient
    @type public_key n-tuple of ints

    @return list of ints representing encrypted bytes
    """
    raise NotImplementedError  # Your implementation here

def decrypt_mh(message, private_key):
    """Decrypt an incoming message using a private key

    1. Extract w, q, and r from the private key
    2. Compute s, the modular inverse of r mod q, using the
        Extended Euclidean algorithm (implemented at `utils.modinv(r, q)`)
    3. For each byte-sized chunk, compute
         c' = cs (mod q)
    4. Solve the superincreasing subset sum using c' and w to recover the original byte
    5. Reconsitite the encrypted bytes to get the original message back

    @param message Encrypted message chunks
    @type message list of ints
    @param private_key The private key of the recipient
    @type private_key 3-tuple of w, q, and r

    @return bytearray or str of decrypted characters
    """
    raise NotImplementedError  # Your implementation here

def encrypt_scytale(plaintext, circumference):
    if not isinstance(plaintext, str):
        raise TypeError("plaintext must be a string")
    ciphertext = ""
    act = 0
    n = len(plaintext)
    for i in range(0, n):
        ciphertext += plaintext[act]
        if (act  + circumference) < len(plaintext):
            act += circumference
        else:
            act = act % circumference + 1
    return ciphertext

def decrypt_scytale(ciphertext, circumference):
    if not isinstance(ciphertext, str):
        raise TypeError("plaintext must be a string")
    n = len(ciphertext)
    plaintext = ""
    rows = n // circumference
    rest = n % circumference
    pos = 0
    for i in range(n):
        plaintext += ciphertext[pos]
        if(i % circumference < rest): pos += rows + 1
        else: pos += rows
        if pos >= n : pos -= n - 1 
    return plaintext

def encrypt_railfence(plaintext, num_rails):
    if not isinstance(plaintext, str):
        raise TypeError("plaintext must be a string")
    ciphertext = ""
    n = len(plaintext)
    if num_rails <= 1 or num_rails >= n:
        return plaintext
    cycle = 2 * (num_rails - 1)
    for rail in range(num_rails):
        # szamoljuk a tavolsagokat egy sorban
        # minden ciklus 2x erint egy sort
        # tavolsagok valtakoznak az iranytol hogy le-fel | fel-le megyunk
        gaps = []
        if(cycle - 2 * rail) > 0:
            gaps.append(cycle - 2 * rail)
        if(rail * 2) > 0:
            gaps.append(2 * rail)
        pos = rail
        k = 0
        while(pos < n):
            ciphertext += plaintext[pos]
            pos += gaps[k % len(gaps)]
            k += 1
    return ciphertext

def decrypt_railfence(ciphertext, num_rails):
    if not isinstance(ciphertext, str):
        raise TypeError("plaintext must be a string")
    n = len(ciphertext)
    if(num_rails <= 1 or num_rails >= n):
        return ciphertext
    
    cycle = 2 * (num_rails - 1)
    
    # melyik pozicio melyik sorba tart:
    pattern = []
    for i in range(n):
        pos = i % cycle
        pattern.append(pos if pos < num_rails else cycle - pos)
   
    # ki kell szamolni egy-egy sorban hany karakter van, es felosztjuk olyan hosszra
    rails = []
    pos = 0
    for r in range(num_rails):
        length = pattern.count(r)
        rails.append(ciphertext[pos:pos + length])
        pos += length

    # dekodoljuk a szoveget
    plaintext = ""
    used = [0] * num_rails
    for r in pattern: # a minta alapjan
        plaintext += rails[r][used[r]]
        used[r] += 1

    return plaintext

