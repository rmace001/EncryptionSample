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
    # encryptedLetter   = plainLetter     ^ public_encrypt_exponent  Mod m
    # plainLetter       = encryptedLetter ^ private-decrypt_exponent Mod m
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
        return '-'.join(
            [str(n) for n in [self.getNextLetter(elem=elem, duringEncryption=True) for elem in inputString]])

    def decryptionWithPartyBPublicKey(self, inputString: str = None):
        return ''.join([str(self.getNextLetter(elem=n, duringEncryption=False)) for n in inputString.split('-')])

    def getNextLetter(self, elem: str = None, duringEncryption: bool = False):
        return int(self.alphabet_dict[elem]) ** self.encryptionExponent % self.m if duringEncryption \
            else self.alphabet[int(elem) ** self.decryptionExponent % self.m]


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

    testRSA = False
    testCeasar = True

    if testRSA:
        message = "dont speak unless you can improve silence"
        print("Encrypted message: ")
        encryptor = rsaEncrypt(p=7, q=19, encryptionExponent=5)

        encryptedMessage = encryptor.encryptionWithPartyBPublicKey(inputString=message)
        print(encryptedMessage)

        print("Decrypted message: ")
        decryptedMessage = encryptor.decryptionWithPartyBPublicKey(inputString=encryptedMessage)
        print(decryptedMessage)

    if testCeasar:
        testCase0 = "hello world"
        shift0 = 1

        testCase1 = "z"
        shift2 = 5

        testCase2 = "zoom"
        shift1 = 10

        testCase3 = "i can do this all day"
        shift = 4242

        testCases = ["hello world", "z", "zoom", "i can do this all day"]
        shifts = [-1, -5, -10, -4242]

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
