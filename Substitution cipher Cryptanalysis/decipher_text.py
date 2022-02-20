# Write your script here
import random
import re
import sys
import json
import time
from math import log10

#Finds the content written in the file in the form of a string
def content(filename):
    fp = open(filename, 'r')
    lines = fp.readlines()
    s = ""
    for l in lines:
        s += l
    return s


#Return the ngrams_score_map and N
def ngrams_score_map(ngramfilename):
    ngrams = {}
    N = 0
    for line in open(ngramfilename):
        x = line.split()
        ngrams[x[0]] = x[1]

        N += int(x[1])
    ngrams_scoreMap = {}
    for ng in ngrams:
        ngrams_scoreMap[ng] = log10(float(ngrams[ng])/N)
    return (ngrams_scoreMap, N)


def getScore(text, ngrams_scoreMap, floor):
    scr = 0
    for i in range(0, len(text)-3):
        txt = text[i:i+4]
        if(txt in ngrams_scoreMap):
            scr += ngrams_scoreMap[txt]
        else:
            scr += floor
    return scr


#Returns a map which contains the characters which will be used in the modified ciphertext to be passed in the algorithm along with the list of the new cipher characters
def modify_cipherCharacters(cipher_characters):
    modified_cipher_characters_map = {}
    new_cipher_characters = []
    i = 97
    for c in cipher_characters:
        new_cipher_characters.append(chr(i))
        modified_cipher_characters_map[c] = chr(i)
        i += 1
    return (modified_cipher_characters_map, new_cipher_characters)

#Removes spaces
def modify(modified_ciphertext):
    finalModified = ""
    for m in modified_ciphertext:
        if(m==" "):
            pass
        else:
            finalModified += m
    return finalModified

#Modifies the ciphertext by replacing all the special characters with the new_cipher_characters which are the letters of the english alphabet
def modifyCiphertext(text, cipher_characters, modified_cipher_characters):
    new_text = ""
    for s in text:
        if s in cipher_characters:
            new_text += modified_cipher_characters[s]
        else:
            new_text += s
    return new_text

#This function gives the pure ciphertext which contains only the characters which are given to us as ciphertext characters
def pureciphertext(text,cipher_characters):
    new_text = ""
    for s in text:
        if s in cipher_characters:
            new_text += s
    return new_text

#Finding the frequency of single letters in the pure ciphertext
#Order of Frequency of single letters: ETAOINSHRDLCUMWFGYPBVKJXQZ
def frequency_singleLetters(new_text, cipher_characters):
    freq = {}
    for c in cipher_characters:
        freq[c] = 0
    for s in new_text:
        freq[s] += 1
    return sorted(freq.items(), key = lambda k:(k[1],k[0]), reverse= True)

#Decrypts the ciphertext when the key is known
def decryptText(ciphertext, key , plain_characters, cipher_characters):
    reverse_substitutions = {}
    for i in range(0,len(key)):
        reverse_substitutions[key[i]] = plain_characters[i]
    plaintext = ""
    for c in ciphertext:
        if c in cipher_characters:
            plaintext += reverse_substitutions[c]
        else:
            plaintext += c
    return plaintext

#Returns the key made up of the actual cipher characters given, not the charcaters of the english alphabets which we substituted for running the algorithm
def unmodifiedKey(Key, modified_cipher_characters_map):
    rev = {}
    for m in modified_cipher_characters_map:
        rev[modified_cipher_characters_map[m]] = m
    str = Key
    final = ""
    for s in str:
        final += rev[s]
    return final

#Chekcs whether all the words in the decrypted text are present in the dictionary or not
def allInDictionary(deciphered_text, dictionary, plain_characters):
    result = True
    word = ""
    for s in deciphered_text:
        if s in plain_characters:
            word += s
        else:
            if(word != ""):
                if(dictionary.get(word,0) == 1):
                    word = ""
                else:
                    return False
    return result


def mainFunction(ciphertext):
    timeout = 250
    timeout_start = time.time()
    plain_characters = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']
    cipher_characters = ['1','2','3','4','5','6','7','8','9','0','@','#','$','z','y','x','w','v','u','t','s','r','q','p','o','n']
    modified_cipher_characters_map, new_cipher_characters = modify_cipherCharacters(cipher_characters)

    modified_ciphertext = modifyCiphertext(ciphertext, cipher_characters, modified_cipher_characters_map)

    pureModified_ciphertext = pureciphertext(modified_ciphertext, new_cipher_characters)

    cipherText_tobePassed = modify(modified_ciphertext)

    f = open('dict.json')
    dictionary = json.load(f)

    ngrams_scoreMap, N = ngrams_score_map('english_quadgrams.txt')
    floor = log10(0.01/N)

    freq_singleLetters = frequency_singleLetters(pureModified_ciphertext, new_cipher_characters)

    OfF_singleLetters = "etaoinshrdlcumwfgypbvkjxqz"
    substitutions = {}
    i = 0
    for f in freq_singleLetters:
        substitutions[OfF_singleLetters[i]] = f[0]
        i += 1
    MKey = []
    for p in plain_characters:
        MKey.append(substitutions[p])
    MScore = -99e9

    ParScore = MScore
    ParKey = MKey

    deciphered_text = ""
    deciphered_key = ""

    i = 0

    deciphered_text = ""
    deciphered_key = ""

    while (time.time() < timeout_start + timeout):
        i = i+1
        random.shuffle(ParKey)
        decryptedText = decryptText(cipherText_tobePassed , ParKey , plain_characters, new_cipher_characters)
        ParScore = getScore(decryptedText.upper(), ngrams_scoreMap, floor)
        itr = 0
        while itr < 1000:
            ChKey = ParKey[:]
            a = random.randint(0,25)
            b = random.randint(0,25)
            k = ChKey[a]
            ChKey[a] = ChKey[b]
            ChKey[b] = k
            decryptedText = decryptText(cipherText_tobePassed , ChKey , plain_characters, new_cipher_characters)
            score = getScore(decryptedText.upper(), ngrams_scoreMap, floor)

            if score <= ParScore:
                itr = itr+1
            else:
                ParScore = score
                ParKey = ChKey[:]
                itr = 1

        # keep track of best score seen so far
        if ParScore <= MScore:
            pass
        else:
            MScore,MKey = ParScore,ParKey[:]
            #print('\nbest score so far:',MScore,'on iteration',i)
            deciphered_text = decryptText(modified_ciphertext, MKey , plain_characters, new_cipher_characters)
            deciphered_key = unmodifiedKey(MKey, modified_cipher_characters_map)
            #print('    best key: '+''.join(MKey))
            #print('    plaintext: '+ deciphered_text )
            if(allInDictionary(deciphered_text, dictionary, plain_characters) == True):
                return deciphered_text, deciphered_key

    return deciphered_text, deciphered_key


class DecipherText(object): # Do not change this

    def decipher(self, ciphertext): # Do not change this
        """Decipher the given ciphertext"""

        # Write your script here
        deciphered_text, deciphered_key = mainFunction(ciphertext)

        print("Ciphertext: " + ciphertext) # Do not change this
        print("Deciphered Plaintext: " + deciphered_text) # Do not change this
        print("Deciphered Key: " + deciphered_key) # Do not change this

        return deciphered_text, deciphered_key # Do not change this

if __name__ == '__main__': # Do not change this
    a = DecipherText() # Do not change this
    f = open('example.txt','r')
    str = "".join(f.readlines())
    #print(str)
    a.decipher(str)
