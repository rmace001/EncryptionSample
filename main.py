#!/usr/bin/python3
# -*- coding: utf-8 -*-
# *****************************************************************************/
# * Copyright 2021 Rogelio Macedo All Rights Reserved.
# * Closed source repository. Do not share any content without permission written from Joseph Tarango.
# * Authors: Rogelio Macedo
# * Template credit: Joseph Tarango
# *****************************************************************************/

'''
input an encoded string and you're going to decode it

given is a string and an offset to use, can go positive or negative, that's 2 questions

can allow all options, postive or negative, or either, or both
'''

import os, sys, datetime, pprint
import string
import traceback
import json

class rsaEncrypt(object):
    # Create alphabet array with space character as the 26th element
    # Also create a dictionary for each (key: letter, value: letter index) pair
    alphabet = list(string.ascii_lowercase) + [" "]
    alphabet_dict = {list(string.ascii_lowercase)[i]: i for i in range(len(list(string.ascii_lowercase)))}
    alphabet_dict[" "] = 26

    def __init__(self, p: int = None, q: int = None, encryptionExponent: int = None):
        self.p, self.q, self.encryptionExponent = p, q, encryptionExponent
        self.m = p*q
        self.f_n = (p - 1) * (q - 1)
        self.publicKey = (encryptionExponent, self.m)
        self.decryptionExponent = self.findMod()
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

        # should do real mod arithmitic here not a while loop

    def findMod(self):
        mod = -1
        i = 0
        while not mod == 1:
            i += 1
            mod = (self.encryptionExponent * i) % self.f_n
        return i

    def encryptionWithPartyBPublicKey(self, inputString: str = None):
        return '-'.join([str(n) for n in [self.getNextLetter(elem=elem, duringEncryption=True) for elem in inputString]])

    def decryptionWithPartyBPublicKey(self, inputString: str = None):
        return ''.join([str(self.getNextLetter(elem=n, duringEncryption=False)) for n in inputString.split('-')])

    def getNextLetter(self, elem: str = None, duringEncryption: bool = False):
        '''
        # encryptedLetter   = plainLetter     ^ public_encrypt_exponent  Mod m
        # plainLetter       = encryptedLetter ^ private-decrypt_exponent Mod m
        :param elem: the next letter to encrypt
        :param duringEncryption:
        :return:
        '''
        return int(self.alphabet_dict[elem]) ** self.encryptionExponent % self.m if duringEncryption \
            else self.alphabet[int(elem) ** self.decryptionExponent % self.m]


class CeaCipher(object):
    alphabet = list(string.ascii_lowercase) + [" "]
    alphabet_dict = {list(string.ascii_lowercase)[i]: i for i in range(len(list(string.ascii_lowercase)))}
    alphabet_dict[" "] = 26

    def __init__(self, shift):
        self.shift = ""
        self.setShift(shift=shift)
        return

    def setShift(self, shift):
        if abs(shift) > len(self.alphabet):
            self.shift = abs(shift) % len(self.alphabet)
            if shift < 0:
                self.shift *= -1
        else:
            self.shift = shift
        return

    def encodeMessage(self, message):
        indices = list()
        for i, m in enumerate(message):
            idx = self.alphabet_dict[m] + self.shift
            if abs(idx) >= len(self.alphabet):
                idx = idx - len(self.alphabet)
            indices.append(idx)
        return "".join([str(self.alphabet[i]) for i in indices])

    def decodeMessage(self, message):
        indices = list()
        for i, m in enumerate(message):
            idx = self.alphabet_dict[m] - self.shift
            if abs(idx) >= len(self.alphabet):
                idx = idx - len(self.alphabet)
            indices.append(idx)
        return "".join([str(self.alphabet[i]) for i in indices])

def main():
    ##############################################
    # Main function, Options
    ##############################################

    # None


    ##############################################
    # Main
    ##############################################

    # deciphering a message
    # what did dr strange mean when he raised up one finger?
    # one question could be to find the private decrypt exponent based on the values and formulas=
    # i.e., Person B's private key

    # another question could be to use the RSA encrypt/decrypt formulas to uncover the message
    # stephenMessage = "if i tell you what happens it wont happen"
    strangeMessage = "your life was spared for this moment take action and follow your instincts"
    print(strangeMessage)

    testRSA = False
    testCeasar = True
    if testRSA:
        # print encrypted message:
        print("Encrypted message: ")
        encryptor = rsaEncrypt(p=7, q=19, encryptionExponent=5)

        encryptedMessage = encryptor.encryptionWithPartyBPublicKey(inputString=strangeMessage)
        print(encryptedMessage)

        # print decrypted message:
        print("Decrypted message: ")
        decryptedMessage = encryptor.decryptionWithPartyBPublicKey(inputString=encryptedMessage)
        print(decryptedMessage)
        pprint.pprint(encryptor)

    if testCeasar:
        string = "test"
        cc = CeaCipher(shift=55)
        cc1 = CeaCipher(shift=-3)

        em = cc.encodeMessage(message="great to be here")
        print(em)
        em = cc.decodeMessage(message="hsfbuaupacfaifsf")
        print(em)
        em = cc1.encodeMessage(message="great to be here")
        print(em)
        em = cc1.decodeMessage(message="dobyqxqlxzbxebob")
        print(em)
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

