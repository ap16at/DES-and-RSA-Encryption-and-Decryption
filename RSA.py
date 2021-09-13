# Andrew Perez-Napan
# ap16at
# Due Date: 3-31-21
# The program in this file is the individual work of Andrew Perez-Napan]
# When minimum value is 5 digits or longer, program takes forever to run.


import random


# Checks if a number is prime
def isPrime(n):
    for i in range(2,int(n**0.5)+1):
        if n%i==0:
            return False
    return True


# Returns the greatest common denominator of two numbers
def gcd(num1, num2):
    if num1 % num2 == 0:
        return num2
    else:
        return gcd(num2, num1 % num2)


# Returns the lowest common multiple of two numbers
def lcm(num1, num2):
    if num1 > num2:
        g = num1
    else:
        g = num2
    while(True):
        if((g % num1 == 0) and (g % num2 == 0)):
            lcm = g
            break
        g += 1
    return lcm


class RSA:
    def __init__(self, e = 0, d = 0):
        self.e = e
        self.d = d
        self.msgList = []


    # Decorator for Encrypted
    def decoratorE(self, func):
        def func_wrapper(num):
            return "The encrypted " + func(num)
        return func_wrapper


    # Decorator for Decrypted
    def decoratorD(self, func):
        def func_wrapper(num):
            return "The decrypted " + func(num)
        return func_wrapper


    # Takes in the numbers that need to be encrypted and decrypted
    def inputFunc(self):
        num_msg = input("Enter the number of messages: ")
        print("Enter the messages:")
        for i in range(int(num_msg)):
            self.msgList.append(input())


    # Prints what the message is
    def printFunc(self, num):
        return "message is " + str(num)


    # Generator function that creates prime numbers
    def primeGen(self, minNum):
        self.p = int(minNum)
        while not isPrime(int(self.p)):
            self.p += 1
        self.q = self.p + 1
        while not isPrime(int(self.q)):
            self.q += 1
        return (self.p, self.q)


    # Generator function that creates the keys for the encryption and decryption
    def keyGen(self, min):
        # p,q = self.primeGen(min)
        self.p = 67
        self.q = 79
        self.e = 19
        self.n = self.p * self.q
        self.t = lcm((self.p - 1), (self.q - 1))
        # self.e = random.randint(1, self.t)
        while gcd(self.e, self.t) != 1:
            self.e = random.randint(1, self.t)
        self.d = 0
        while (self.e * self.d % self.t) != 1:
            self.d += 1
        print("N is ", self.n)
        print("e is ", self.e)
        print("d is ", self.d)
        return (self.n, self.e, self.d)

    # Encrypts using the keys
    def encrypt(self, num):
        self.c = (int(num) ** int(self.e)) % int(self.n)
        return self.c
    

    # Decrypts using the keys
    def decrypt(self, num):
        self.m = (int(num) ** int(self.d)) % int(self.n)
        return self.m


    # Messages that iterates through the messages and encrypts them and decrypts them
    def messages(self):
        self.inputFunc()

        minNum = input("Enter the minimum value for the prime numbers: ")

        self.keyGen(minNum)

        self.encryptedMsg = []

        for num in self.msgList:
            self.encryptedMsg.append(self.encrypt(num))

        self.decryptedMsg = []

        for num in self.encryptedMsg:
            temp = self.decoratorE(self.printFunc)
            print(temp(num))
            self.decryptedMsg.append(self.decrypt(num))

        for num in self.decryptedMsg:
            temp = self.decoratorD(self.printFunc)
            print(temp(num))


if __name__ == "__main__":
    rsa = RSA()
    rsa.messages()