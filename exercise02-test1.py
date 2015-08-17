import sys


##Many Time Pad

##Let us see what goes wrong when a stream cipher key is used more than once. Below are eleven hex-encoded ciphertexts that are the result of encrypting eleven plaintexts with a stream cipher, all with the same stream cipher key. Your goal is to decrypt the last ciphertext, and submit the secret message within it as solution.

##Hint: XOR the ciphertexts together, and consider what happens when a space is XORed with a character in [a-zA-Z].


print 'Week 1 - Excercise 2'

MSGS = [None] * 11

ciphertext1 = '315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e'
ciphertext2 = '234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f'
ciphertext3 = '32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb'
ciphertext4 = '32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa'
ciphertext5 = '3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070'
ciphertext6 = '32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e436434eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4'
ciphertext7 = '32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce'
ciphertext8 = '315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3'
ciphertext9 = '271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027'
ciphertext10 = '466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83'

targetCiphertext = '32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904'

MSGS[0] = ciphertext1;
MSGS[1] = ciphertext2;
MSGS[2] = ciphertext3;
MSGS[3] = ciphertext4;
MSGS[4] = ciphertext5;
MSGS[5] = ciphertext6;
MSGS[6] = ciphertext7;
MSGS[7] = ciphertext8;
MSGS[8] = ciphertext9;
MSGS[9] = ciphertext10;
MSGS[10] = targetCiphertext;


clave = '66396e89c9dbd8cc9874352acd6395102eafce78aa7fed28a07f6bc98d29c50b69b0339a19f8aa401a9c6d708f80c066c763fef0123148cdd8e802d05ba98777335daefcecd59c433a6b268b60bf4ef03c9a611098bb3e9a3161edc7b804a33522cfd202d2c68c57376edba8c2ca50027c61246ce2a12b0c4502175010c0a1ba4625786d911100797d8a47e98b0200c4ab000000a900000000008a0082d10000320000000000000000050000911f3edfd73e8333e8463df984ee'

def strxor(a, b):  # xor two strings of different lengths
    result = ""
    if len(a) > len(b):
        result = "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        result = "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])

    return result


def random(size=16):
    return open("/dev/urandom").read(size)


def encrypt(key, msg):
    c = strxor(key, msg)
    print
    print c.encode('hex')
    return c

def decrypt(key, ct):
    m = strxor(key, ct)
    return m



def main():
    key = random(1024)
    ciphertexts = [encrypt(key, msg) for msg in MSGS]

def applyXOR(ciphertext, allCiphertext):
    result = ciphertext
    for ct in allCiphertext:
        if ct != ciphertext:
            result = strxor(result, ct)
    return result


def xorTogether(entry):
    ciphertexts = entry[0]
    for i in range(1, len(entry)-1):
        ciphertexts = strxor(ciphertexts, entry[i])
    return ciphertexts


def stringToHex(stringinput):
    try:
        result = '';
        for letter in stringinput:
            result = result + format(ord(letter), "x") + "-"
        return result
    except:
        return '<-YRCH->'


def hexToString(hexinput):
    return hexinput.encode("hex")


##main();

##xorTogether();

def showInformation(chr):
    try:
        if ord(chr) == 20:
            return ' is a space'
        if ord(chr) < 32:
            return ' is a Control character'
        if ord(chr) >= 32 and ord(chr) < 64:
            return chr + ' is a symbol'
        if ord(chr) >=65 and ord(chr) <= 90:
            return chr + ' is a UpperCase'
        if ord(chr) >=97 and ord(chr) <= 122:
            return chr + ' is a lowercase'
        return chr + ' is other thing'
    except:
        print "Unexpected error:", sys.exc_info()[0]
        raise

def test1(stringsToTest):
    for c1 in stringsToTest:
        for c2 in stringsToTest:
            aux = strxor(c1, c2)
            if ord(c2) == 0:
                c2 = "null"
            else:
                if ord(c2) == 0x20:
                    c2 = "space"
            aux1 = c1
            if ord(aux1) == 0:
                aux1 = "null"
            else:
                if ord(aux1) == 0x20:
                    aux1 = "space"
            print '' + aux1 + ' xor ' + c2 + " = " + showInformation(aux)


def test2():
    for x in range(26):
        print '%s' % chr((ord('a')+x) ^ ord(' ')),

    print '\n'

    for x in range(26):
        print '%s' % chr((ord('A')+x) ^ ord(' ')),

    print '\n'


def isALetter(chr):
    return chr.isalpha()

def isNull(chr):
    return ord(chr) == 0





def detectCrib(c1, c2):
    result = ""
    newOne = strxor(c1, c2)
    for letter in newOne:
        if isALetter(letter):
            result += "_"
        else:
            result += "X"
    return result


def parseHints(lista):
    result = ""
    for i in range(len(lista[0])):
        aux = True
        for j in range(len(lista)):
            if i < len(lista[j]):
                aux = aux and lista[j][i]== "_"

        if aux:
            result += '_'
        else:
            result += 'X'

    return result


def  detectSpaces(ct,allCipherText):
    aux = []
    for ct2 in allCipherText:
        if ct != ct2:
            aux.append(detectCrib(ct,ct2))

    spaces = parseHints(aux)

    return spaces


def metodo1 (c1,c2,cribs):
    nose = ''
    if c1 != c2:
        s1 = strxor(c1,c2)
        lon = len(cribs)
        if lon >len(s1):
            lon = len(s1)

        for i in range(lon-1):
            if cribs[i] == 'M' and isALetter(s1[i]):
                if s1[i].islower():
                    nose += s1[i].upper()
                else:
                    nose += s1[i].lower()

            else:
                nose += "="

    return nose


stringsToTest = ['a', 'A', 'z', 'Z', ' ','\00']

test1(stringsToTest)
test2()
print '\n'


print detectSpaces(targetCiphertext,MSGS)



