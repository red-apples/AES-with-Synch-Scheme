import collections
import operator
import csv

# from AESOO import AES as aes
import AES as aes

# IV Fill is the original fill of IV
# Change as required.

IVFill = "FAFAFAFAFAFAFAFAFAFAFAFAFAFAFAFA"

# Working Registers
ARRAY1 = collections.deque([], 128)
ARRAY2 = collections.deque([], 128)
ARRAY3 = collections.deque([0, 0], 128)
ARRAY4 = collections.deque([], 128)

# Simulates Delta function
deltaTx = collections.deque([0, 0], 2)
deltaRx = collections.deque([0, 0], 2)

# Holds Cipher text
cipherText = collections.deque([], 128)

# Arrays required only for writing to CSV files
cipherTextAll = collections.deque([])
tempTx = collections.deque([])
PTOut = collections.deque([])
PTIn = collections.deque(
    [1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0,
     0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1,
     0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1,
     1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0,
     1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0,
     0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1,
     0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1,
     1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0,
     1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0])


def putCTintoArray(Array, CT):
    binCT = CT
    for i in range(0, len(binCT)):
        Array.append(int(binCT[i:i + 1], 2))

def invert(bitIn):
    if bitIn == 1:
        bitIn = 0
        return bitIn
    elif bitIn == 0:
        bitIn = 1
        return bitIn


def fillIV(Array, IV):
    binValue = hexToBinNonSize(IV, 16)
    putCTintoArray(Array, binValue)


def hexToBin(text, base, size):
    return bin(int(text, base))[2:].zfill(size)


def hexToBinNonSize(text, base):
    return bin(int(text, base))[2:]


def binArrayToHex(Array, base, size):
    return hex(int("".join(map(str, Array)), base))[2:].zfill(size)


def concatention(a, b):
    a = a << 84
    a = a | b
    return a


def arrayToBin(Array, base, size):
    return bin(int("".join(map(str, Array)), base))[2:].zfill(size)


def transmit(i):
    # cK = aes.g_ck
    cK = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    Nr = 14
    Nk = 8
    Nb = 4
    ptBit = PTIn[i]
    codebookIn = binArrayToHex(ARRAY1, 2, 32)
    tempTx.append(codebookIn)
    codebookOut = aes.Encrypt(cK, Nk, Nb, Nr, codebookIn)
    codebookOut = hexToBin(codebookOut, 16, 128)
    putCTintoArray(ARRAY2, codebookOut)
    codebookOutBit = ARRAY2[127]
    writeKeystream(i, codebookOutBit, ARRAY2[0])
    outBit = operator.xor(ptBit, codebookOutBit)
    inputBit = invert(outBit)
    ARRAY1.append(inputBit)
    cipherText.append(outBit)
    cipherTextAll.append(outBit)


def receive(i):
    cK = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    Nr = 14
    Nk = 8
    Nb = 4
    codebookIn = binArrayToHex(ARRAY3, 2, 32)
    writeRegister(i, codebookIn)
    codebookOut = aes.Encrypt(cK, Nk, Nb, Nr, codebookIn)
    writeAESCT(i, codebookOut)
    codebookOut = hexToBin(codebookOut, 16, 128)
    putCTintoArray(ARRAY4, codebookOut)
    codebookOutBit = ARRAY4[127]
    cipherTextBit = cipherText.pop()
    ptBit = operator.xor(codebookOutBit, cipherTextBit)
    PTOut.appendleft(ptBit)
    ct = invert(cipherTextBit)
    ARRAY3.append(ct)
    writeWhileAppending(i)


def synchSim():
    initiateCSV()
    for i in range(0, 300, 1):
        transmit(i)
        receive(i)

# === FILE WRITING === #
# Initialises .csv files and writes to csv file

def initiateCSV():
    csv_path = '../data/pt.csv'
    with open(csv_path, 'w') as file_obj:
        writer = csv.DictWriter(file_obj, delimiter="\t", fieldnames=["i", "Tx", "Rx", "CT"])
        headers = {}
        for n in writer.fieldnames:
            headers[n] = n
        writer.writerow(headers)
    csv_path = '../data/register.csv'
    with open(csv_path, 'w') as file_obj:
        writer = csv.DictWriter(file_obj, delimiter="\t", fieldnames=["Index", "Register"])
        headers = {}
        for n in writer.fieldnames:
            headers[n] = n
        writer.writerow(headers)
    csv_path = '../data/keyStream.csv'
    with open(csv_path, 'w') as file_obj:
        writer = csv.DictWriter(file_obj, delimiter="\t", fieldnames=["i", "ks"])
        headers = {}
        for n in writer.fieldnames:
            headers[n] = n
        writer.writerow(headers)
    csv_path = '../data/AESCipherText.csv'
    with open(csv_path, 'w') as file_obj:
        writer = csv.DictWriter(file_obj, delimiter="\t", fieldnames=["i", "CT"])
        headers = {}
        for n in writer.fieldnames:
            headers[n] = n
        writer.writerow(headers)


def writeWhileAppending(i):
    csv_path = '../data/pt.csv'
    with open(csv_path, 'a') as file_obj:
        writer = csv.DictWriter(file_obj, delimiter="\t", fieldnames=["i", "Tx", "Rx", "CT"])
        writer.writerow({"i": i, "Tx": PTIn[i], 'Rx': PTOut[0], 'CT': cipherTextAll[i]})


def writeRegister(i, regrx):
    csv_path = '../data/register.csv'
    with open(csv_path, 'a') as file_obj:
        writer = csv.DictWriter(file_obj, delimiter="\t", fieldnames=["Index", "Register_tx", "Register_rx"])
        writer.writerow({"Index": i, "Register_tx": tempTx[i], "Register_rx": regrx})


def writeKeystream(i, ks, ks1):
    csv_path = '../data/keyStream.csv'
    with open(csv_path, 'a') as file_obj:
        writer = csv.DictWriter(file_obj, delimiter="\t", fieldnames=["i", "ks"])
        writer.writerow({"i": i, "ks": ks})

def writeAESCT(i, CT):
    csv_path = '../data/AESCipherText.csv'
    with open(csv_path, 'a') as file_obj:
        writer = csv.DictWriter(file_obj, delimiter="\t", fieldnames=["i", "CT"])
        writer.writerow({"i": i, "CT": CT})

if __name__ == "__main__":
    fillIV(ARRAY1, IVFill)
    x = 1
    while x != 0:
        print("Enter '1' Simulation")
        print("Enter '0' To Exit ")
        x = int(input("Please enter your choice: "))
        if x == 1:
            print("1 was entered. ")
            synchSim()
        elif x == 0:
            print("Exiting. ")
            exit()
        else:
            print("Please enter a valid number. ")
        print("-------------------------")