#!/usr/bin/python3
# -*- coding: utf-8 -*-
# *****************************************************************************/
# * Copyright 2021 Rogelio Macedo All Rights Reserved.
# * Closed source repository. Do not share any content without permission.
# * Authors: Rogelio Macedo
# * Template credit: Joseph Tarango
# *****************************************************************************/

import datetime, pprint
import string
import traceback
import json


class rsaEncrypt(object):
    # Create alphabet array with space character as the 26th element
    # Also create a dictionary for each (key: letter, value: letter index) pair
    # encryptedValue         = plainLetterIndex  ^ public_encrypt_exponent  Mod m
    # plainLetterIndex       = encryptedValue    ^ private_decrypt_exponent Mod m
    alphabet = list(string.ascii_lowercase) + [" "]
    alphabet_dict = {list(string.ascii_lowercase)[i]: i for i in range(len(list(string.ascii_lowercase)))}
    alphabet_dict[" "] = 26

    def __init__(self, p: int = None, q: int = None, encryptionExponent: int = None):
        self.p, self.q, self.encryptionExponent = p, q, encryptionExponent
        self.m = p * q
        self.f_n = (p - 1) * (q - 1)
        self.publicKey = (encryptionExponent, self.m)
        self.decryptionExponent = self.findDecryptExponent()
        return

    def __repr__(self):
        ret = dict()
        ret["Alphabet"] = self.alphabet
        ret["AlphabetDict"] = self.alphabet_dict
        ret["p"] = self.p
        ret["q"] = self.q
        ret["m"] = self.m
        ret["f(n)"] = self.f_n
        ret["Public Key"] = str(self.publicKey)
        ret["Encryption Exponent"] = self.encryptionExponent
        ret["Dycryption Exponent"] = self.decryptionExponent
        result = json.dumps(ret)
        return result

    def findDecryptExponent(self):
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            else:
                gcd, x, y = extended_gcd(b % a, a)
                return gcd, y - (b // a) * x, x

        gCD, X, Y = extended_gcd(self.encryptionExponent, self.f_n)
        return X + self.f_n

    def encryptionWithPartyBPublicKey(self, inputString: str = None):
        """

        :param inputString: Message to encrypt
        :return: encrypted message where each encrypted letter is shown as a number and is separated by a '-'
        """
        return ','.join(
            [str(n) for n in [self.getNextLetter(elem=elem, duringEncryption=True) for elem in inputString]])

    def decryptionWithPartyBPublicKey(self, inputString: str = None):
        return ''.join([str(self.getNextLetter(elem=n, duringEncryption=False)) for n in inputString.split(',')])

    def getNextLetter(self, elem: str = None, duringEncryption: bool = False):
        if duringEncryption:
            return int(self.alphabet_dict[elem]) ** self.encryptionExponent % self.m
        else:
            va = int(elem) ** self.decryptionExponent % self.m
            return self.alphabet[int(elem) ** self.decryptionExponent % self.m]
        # return int(self.alphabet_dict[elem]) ** self.encryptionExponent % self.m if duringEncryption \
        #     else self.alphabet[int(elem) ** self.decryptionExponent % self.m]


class CeaCipher(object):
    alphabet = list(string.ascii_lowercase)
    alphabet_dict = {list(string.ascii_lowercase)[i]: i for i in range(len(list(string.ascii_lowercase)))}

    def __init__(self, shift):
        self.shift = self.setShift(shift=shift)
        return

    def setShift(self, shift):
        """
        Set initial shift value for ceasar cipher
        :param shift:
        :return:
        """
        return (1 if shift > 0 else -1) * (abs(shift) % len(self.alphabet)) if abs(shift) > len(self.alphabet) \
            else shift

    def encodeMessage(self, message):
        return self.encodeOrDecode(message=message, option="e")

    def decodeMessage(self, message):
        return self.encodeOrDecode(message=message, option="d")

    def encodeOrDecode(self, message: str, option: str):
        optionSwitch = 1 if option == "e" else -1
        return "".join([str(self.alphabet[i]) for i in self.getIndices(message, optionSwitch)])

    def getIndices(self, message, optionSwitch):
        for m in message:
            idx = self.alphabet_dict[m] + (optionSwitch * self.shift)
            if abs(idx) >= len(self.alphabet):
                idx = idx - len(self.alphabet)
            yield idx


def main():
    ##############################################x
    # Main function, Options
    ##############################################

    # None

    ##############################################
    # Main
    ##############################################

    testRSA = True
    testCeasar = True

    if testRSA:
        message = "dont speak unless you can improve silence"
        testCases = [
            "on your left",
            "i am iron man",
             "Part of the journey is the end".lower(),
             "Tony trying to get you to stop has been one of the few failures of my entire life".lower(),
             "No amount of money ever bought a second of time".lower(),
             "You know I keep telling everybody they should move on and grow".lower(),
             "no mistakes"]
        encryptor = rsaEncrypt(p=7, q=19, encryptionExponent=5)
        for i in range(len(testCases)):
            encryptedMessage = encryptor.encryptionWithPartyBPublicKey(inputString=testCases[i])
            print(encryptedMessage)

            print("Decrypted message: ")
            decryptedMessage = encryptor.decryptionWithPartyBPublicKey(inputString=encryptedMessage)
            print(decryptedMessage)

    if testCeasar:
        testCases = ["hello world", "apple", "i can do this all day", "on your left", "doth mother know you weareth her drapes", "WE ARE NOT AGENTS OF NOTHING WE ARE AGENTS OF SHIELD AND THAT STILL CARRIES WEIGHT IT HAS TO CARRY WEIGHT".lower()]
        shifts = [1, 5, 4242, 56432, 1234, 1111]

        testCases = ["on your left",
                     "Part of the journey is the end".lower(),
                     "Tony trying to get you to stop has been one of the few failures of my entire life".lower(),
                     "No amount of money ever bought a second of time".lower(),
                     "You know I keep telling everybody they should move on and grow".lower(),
                     "no mistakes"]
        shifts = [-3, -223, -34, 54433, -88888, 12345]
        for i in range(len(testCases)):
            cc = CeaCipher(shift=shifts[i])

            em = " ".join(cc.encodeMessage(message=word) for word in testCases[i].split())
            print(em)

            dm = " ".join(cc.decodeMessage(message=word) for word in em.split())
            print(dm)

        print(" ".join(letter for letter in cc.alphabet))
    return


if __name__ == '__main__':
    """Performs execution delta of the process."""
    pStart = datetime.datetime.now()
    try:
        main()
    except Exception as errorMain:
        print("Fail End Process: {0}".format(errorMain))
        traceback.print_exc()
    qStop = datetime.datetime.now()
    print("Execution time: " + str(qStop - pStart))
