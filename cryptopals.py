import sys 
import base64
from codecs import encode, decode
import binascii

if(2 > len(sys.argv)):
    print("too few args")
    exit()
else:
    arg1 = sys.argv[1]
    arg2 = sys.argv[2]

#Cryptopals chal 1: hex to b64
def hex_to_b64(hex_input): 
    hex_input_bytes = decode(hex_input, 'hex')
    #base64_bytes = base64.b64encode(hex_input_bytes)
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
        output2 = output.decode('utf8')
        return output2

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

    assert(len(a_str) == len(b_str))
    dist = 0 
    for b1,b2 in zip(a_str,b_str):
        diff = b1^b2
        dist += sum((1 for bit in bin(diff) if bit == '1'))

    return dist

def break_repeating_xor():
    return 

def main():
    #hex_input = arg1
    #print(single_byte_xor(hex_input))
    #single_character_xor()
    #repeating_key_xor(hex_input)
    a = "this is a test"
    b = "wokka wokka!!!"
    a_byte = bytes(a, 'utf-8')
    b_byte = bytes(b, 'utf-8')
    print(hamming_dist(a_byte,b_byte))
    #break_repeating_xor()

if __name__=='__main__':
    main()
