import csv
import operator

# Input 128bit  block, following NIST spec
inputBytes = "00112233445566778899aabbccddeeff"
# Cipher Key Used
g_cK = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

# Global  variable, holding Round Keys produced by Cipher Key expansion
g_cipherKeyDic = {}

# Global variables, Nr being Number of rounds performed, Nk being number of 32-bit words,
# and Nb being number of columns in state
g_Nr = 14
g_Nk = 8
g_Nb = 4

# Global Array, substitution box
g_sbox = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]

# Global Matrix, representing fixed polynomial a(x) reference in FIPS 197
g_axMatrix = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]


def InitialiseMatrix(w, h):
    Matrix = [[0 for x in range(w)] for y in range(h)]
    return Matrix


# Given a string, splits into two bytes and inserts into the matrix
def InputTextToMatrix(inputString):
    w, h = g_Nb, g_Nb
    Matrix = InitialiseMatrix(w, h)
    c = 0
    for col in range(0, 4):
        for row in range(0, 4):
            byte = int(inputString[c:c + 2], 16)
            Matrix[row][col] = "{0:#0{1}x}".format(byte, 4)[2::]  # Formats the string as Hex value with leading 0s
            c = c + 2
    return Matrix


# Non-linear transformation, substituting bytes into g_sbox
def SubBox(Matrix):
    for col in range(0, 4):
        for row in range(0, 4):
            tempValue = Matrix[row][col]
            newValue = SubBytesSelection(tempValue)
            Matrix[row][col] = "{0:#0{1}x}".format(newValue, 4)[2::]
    return Matrix


# Takes a word, splitting into two bytes. Produces a value to be inputted into g_sbox
# Returns a word from g_sbox
def SubBytesSelection(word):
    assert (len(word) == 2), "Byte length not equal to two! *subBytesSelection() "
    xvalue = int(word[0:1], 16) * 16  # 16 is row length of g_sbox
    yvalue = int(word[1:2], 16)
    value = yvalue + xvalue
    outWord = g_sbox[value]
    return outWord


# Words in the last three rows of the Matrix are cyclically shifted over different number of offsets
# First row is not shifted
def ShiftRow(Matrix):
    for i in range(0, 1, 1):
        shiftValue = Matrix[1].pop(0)
        Matrix[1].append(shiftValue)
    for i in range(0, 2, 1):
        shiftValue = Matrix[2].pop(0)
        Matrix[2].append(shiftValue)
    for i in range(0, 3, 1):
        shiftValue = Matrix[3].pop(0)
        Matrix[3].append(shiftValue)
    return Matrix


# Peasants algorithm implementation of Galois Multiplication
# Used for Mix Columns to treat each column as a fourterm polynomial
def GaloisMulti(a, b):
    p = 0
    for i in range(8):
        if b & 1 == 1:
            p ^= a
        hiBitSet = a & 0x80
        a <<= 1
        if hiBitSet == 0x80:
            a ^= 0x1b
        b >>= 1
    return p % 256


# Transformation operates on the state column-by-column, multiplied by fixed polynomial
# a(x) represented in matrix form as g_axMatrix
def MixColumns(Matrix, axMatrix, Nb):
    tempMatrix = InitialiseMatrix(Nb, Nb)
    for col in range(0, 4):
        newValue = 0
        for row in range(0, 4):
            for count in range(0, 4):
                a = int(Matrix[count][col], 16)
                b = int(axMatrix[row][count])
                tempValue = GaloisMulti(a, b)
                newValue = operator.xor(newValue, tempValue)
            tempMatrix[row][col] = "{0:#0{1}x}".format(newValue, 4)[2::]
            newValue = 0
    return tempMatrix


# Used for Key expansion. Takes four bytes and cyclic shifts by n
def Rotate(string, n):
    string = str(string)
    for i in range(0, n, 1):
        temp1 = string[2::]
        temp2 = string[:2]
        string = temp1 + temp2
    assert (len(string) == 8), "String length not equal to 8! *rotate()"
    return string


# Calculates x^i-1 as powers of x, with x being denoted a 02 in the field GF(2^8)
def Rcon(i):
    x = 2
    n = i - 1
    x = x ** n
    x = "{0:#0{1}x}".format(x, 4)[2::]
    x = "{:<08}".format(x)  # Fills to 8 bits with trailing 0s
    return x


# Takes the Cipher Key and splits into 8 byte words.
def SplitKey(cipherKey, nk):
    len_key = int(len(cipherKey))
    n = int(len_key / nk)
    index = 0
    for i in range(0, len_key, n):
        word = cipherKey[i:i + n]
        assert (len(word) == 8), "String length not equal to 8! "
        g_cipherKeyDic["w{0}".format(index)] = word
        index = index + 1


# Splits the string in order to substitute into sbox
def SplitStringSubBytes(string):
    outString = ""
    for i in range(len(string)):
        if i % 2 == 0:
            inBytes = string[i:i + 2]
            outBytes = SubBytesSelection(inBytes)
            outBytes = "{0:#0{1}x}".format(outBytes, 4)[2::]
            outString = outString + outBytes
    return outString


# Takes the Cipher Key, cK, and performs a Key Expansion routine to generate key schedule
# This generates Nb(Nr+1) words
def KeyExpansion(cK, Nk, Nb, Nr):
    SplitKey(cK, Nk)
    i = Nk
    endRange = Nb * (Nr + 1)
    while i < endRange:
        temp = g_cipherKeyDic["w{0}".format(i - 1)]
        if i % Nk == 0:
            temp = Rotate(temp, 1)
            temp = SplitStringSubBytes(temp)
            rconOut = Rcon(int(i / Nk))
            temp = operator.xor(int(temp, 16), int(rconOut, 16))
            temp = str(hex(temp)[2::])
        elif Nk > 6 and i % Nk == 4:
            temp = SplitStringSubBytes(temp)
        word = int(GetNthValue(i - Nk), 16)
        temp = operator.xor(int(temp, 16), word)
        temp = "{0:#0{1}x}".format(temp, 10)[2::]
        g_cipherKeyDic["w{0}".format(i)] = temp
        i = i + 1


# Adds Round Key to the State through a simple bitwise XOR operation.
def AddRoundKey(state, word):
    stateWhole = ""
    for col in range(0, 4):
        for row in range(0, 4):
            tempValue = str(state[row][col])
            stateWhole = stateWhole + tempValue
    state = operator.xor(int(word, 16), int(stateWhole, 16))
    state = "{0:#0{1}x}".format(state, 34)[2::]
    return state


# Returns the nth value in Cipher Key Dictionary
def GetNthValue(n):
    if n < 0:
        n += len(g_cipherKeyDic)
    for i, value in enumerate(g_cipherKeyDic.values()):
        if i == n:
            return value
    raise IndexError("dictionary index out of range")


# Joins the returned values 32 bit values from GetNthValue into 128 bit word
def CipherKeyWord(n, m):
    temp1 = GetNthValue(n)
    temp2 = GetNthValue(n + 1)
    temp3 = GetNthValue(n + 2)
    temp4 = GetNthValue(n + 3)
    word = temp1 + temp2 + temp3 + temp4
    return word


# Displays the matrix in order to capture state data
def DisplayMatrix(state):
    newValue = ""
    for row in range(0, 4):
        for col in range(0, 4):
            tempValue = str(state[col][row])
            newValue = newValue + tempValue
    return newValue


# Main cipher function. Encrypts the data
def Encrypt(cK, Nk, Nb, Nr, inputBytes):
    KeyExpansion(cK, Nk, Nb, Nr)
    state = InputTextToMatrix(inputBytes)
    # WriteTo(" 0 ", " input ", DisplayMatrix(state))
    # WriteTo(" 0 ", " k_sch ", CipherKeyWord(0, Nb - 1))
    state = InputTextToMatrix(AddRoundKey(state, CipherKeyWord(0, Nb - 1)))
    for ROUND in range(1, Nr):
        # WriteTo(ROUND, " start ", DisplayMatrix(state))
        state = SubBox(state)
        # WriteTo(ROUND, " s_box ", DisplayMatrix(state))
        state = ShiftRow(state)
        # WriteTo(ROUND, " s_row ", DisplayMatrix(state))
        state = MixColumns(state, g_axMatrix, Nb)
        # WriteTo(ROUND, " m_col ", DisplayMatrix(state))
        state = InputTextToMatrix(AddRoundKey(state, CipherKeyWord(ROUND * Nb, (ROUND + 1) * (Nb - 1))))
        # WriteTo(ROUND, " k_sch ", CipherKeyWord(ROUND * Nb, (ROUND + 1) * (Nb - 1)))
    # WriteTo("14", " start ", DisplayMatrix(state))
    SubBox(state)
    # WriteTo("14", " s_box ", DisplayMatrix(state))
    ShiftRow(state)
    # WriteTo("14", " s_row ", DisplayMatrix(state))
    state = InputTextToMatrix(AddRoundKey(state, CipherKeyWord(Nr * Nb, (Nr + 1) * (Nb - 1))))
    # WriteTo("14", " k_sch ", CipherKeyWord(Nr * Nb, (Nr + 1) * (Nb - 1)))
    cipherText = DisplayMatrix(state)
    # WriteTo("14", " out ", DisplayMatrix(state))
    return cipherText


# === FILE WRITING === #
# Initialises .csv files and writes to csv file
def InitiateCSV():
    csv_path = '../data/vectors.csv'
    with open(csv_path, 'w') as file_obj:
        writer = csv.DictWriter(file_obj, delimiter="\t", fieldnames=["ROUND", "Function", "CT"])
        headers = {}
        for n in writer.fieldnames:
            headers[n] = n
        writer.writerow(headers)


def WriteTo(i, func, ct):
    csv_path = '../data/vectors.csv'
    with open(csv_path, 'a') as file_obj:
        writer = csv.DictWriter(file_obj, delimiter="\t", fieldnames=["ROUND", "Function", "CT"])
        writer.writerow({"ROUND": i, 'Function': func, 'CT': ct})


if __name__ == "__main__":
    InitiateCSV()
    Encrypt(g_cK, g_Nk, g_Nb, g_Nr, inputBytes)
