def single_character_xor():

    f = open("out.txt")

    #byte_strings = (binascii.unhexlify(line.strip()) for line in f.readlines())
    #for string in byte_strings:
        #xord_strings = (''.join(chr(a^num) for num in string) for a in range(256))
    strings = (line.strip() for line in f.readlines())
    for string in strings:
        if(string.isascii()):
            #spec_char = "!@#$%^&*()~;[]{}`|:-+?_=,<>"
            #if any (c in spec_char for c in d):
                #continue
            #else:
            print(string)
    f.close()
    return

single_character_xor();
