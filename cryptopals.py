import sys 
import base64
from codecs import encode, decode
import binascii

if(3 > len(sys.argv)):
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


def main():
    hex_input = arg1
    xor_against = arg2
    print(fixed_xor(hex_input, xor_against))


if __name__=='__main__':
    main()
