import sys 
import base64
from codecs import encode, decode
import binascii
import itertools

if(2 > len(sys.argv)):
    print("too few args")
    exit()
else:
    arg1 = sys.argv[1]
    arg2 = sys.argv[2]

#Cryptopals chal 1: hex to b64
def hex_to_b64(hex_input): 
    hex_input_bytes = decode(hex_input, 'hex')
    base64_bytes = encode(hex_input_bytes, 'base64')
    output = base64_bytes.decode('ascii')
    return output

#Cryptopals chal 2: fixed XOR
def fixed_xor(hex_input, xor_against):
    if (len(hex_input) == len(xor_against)):
        hex_input_bytes = decode(hex_input, 'hex')
        xor_against_bytes = decode(xor_against, 'hex')
        
        output_bytes = bytes((a ^ b) for a,b in zip(hex_input_bytes, xor_against_bytes))
        output = binascii.hexlify(output_bytes)
        return output

    else :
        print("string lengths do not match")
        return

def single_byte_xor(hex_input):
    byte_strings = binascii.unhexlify(hex_input)
    strings = (''.join(chr(a^num) for num in byte_strings) for a in range(256)) #creates a generator object of xor'd strings
    return max(strings, key=lambda s: s.count(' ')) #counting spaces for frequency

def single_character_xor():
    
    f = open("4.txt")
        
    byte_strings = (binascii.unhexlify(line.strip()) for line in f.readlines())
    for string in byte_strings:
        xord_strings = (''.join(chr(a^num) for num in string) for a in range(256))
        for d in xord_strings:
            if(d.isascii()):
                spec_char = "!@#$%^&*()~;[]{}`|:-+?_=,<>"
                if any (c in spec_char for c in d):
                    continue
                else:
                    print(d) 
    f.close()
    return

#takes string as arg, make sure you put it in quotes
def repeating_key_xor(hex_input):
    key = "ICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICE"
    
    key_bytes = bytes(key, 'utf-8')
    byte_string = bytes(hex_input, 'utf-8')
    bytes_output = bytes((a ^ b) for a,b in zip(key_bytes, byte_string))
    output = binascii.hexlify(bytes_output)
    print(output) 
    
    return

def hamming_dist(a_str: bytes, b_str: bytes) -> int:
#this function works, do not touch it
    assert(len(a_str) == len(b_str))
    dist = 0 
    for b1,b2 in zip(a_str,b_str):
        diff = b1^b2
        dist += sum((1 for bit in bin(diff) if bit == '1'))

    return dist

def open_txt():
    f = open("6.txt")
    lst = []
    byte_strings = (base64.b64decode(line.strip()) for line in f.readlines())

    f1 = open("byteslist1.txt", 'wb')
    for string in byte_strings:
        f1.write(string)
    f1.close()
    f.close()
    return

def break_repeating_xor(i, test):
    
    f = open("byteslist1.txt", 'r')
    keysize = i
    dist = []
    f1 = f.readlines() #this doesn't work inside the for statement 
    for line in f1:
        l1 = (bytes(line, 'utf-8'))
        l1 = bytes(f1[:keysize], 'utf-8')
        l2 = bytes(f1[keysize:(keysize*2)], 'utf-8')
        dist += hamming_dist(l1, l2)
       
    #an error where hamming_dist wants bytes but the lines in f1 are strings. possibly want one big bytes object that I can feed into chunks into hamming_dist
        print(dist)
    f.close()
    #dist = hamming_dist(first, second)
    #eq = dist/keysize
    
    print(keysize)
    #print(eq)
        
    return #[eq, keysize]

def main():
    #hex_input = arg1
    #print(single_byte_xor(hex_input))
    #single_character_xor()
    #repeating_key_xor(hex_input)
    lst = []
    #test_str = open_txt()
    #for i in range(2, 41):
        #lst += break_repeating_xor(i, test_str)
    break_repeating_xor(1, 'test')
    #print(min(lst))

if __name__=='__main__':
    main()
