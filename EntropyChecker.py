# My first ever Python program
# Written for ZZEN9201 - Foundations of Cyber Security UNSW.
# 
# 25/08/2022    Wrote the first function to read keyboard input and pass the value to a function  
# 04/09/2022    Added functions to count the nuner of uppercase and lowercase letters in the input string
# 11/09/2022    Added functions to count the number of special characters and space in the input string
# 23/09/2022    Used the resource (https://generatepasswords.org/how-to-calculate-entropy/) to understand password entropy
#               formula and used math functions to construct one in Python.
#                       log base 2 of the number of characters in the character set used where char set = 95 (the number of keys
#                       on a keyboard)
# 03/10/2022    Added check_char_set function. This is required to determine the correct value for charset
#               Examples:
#                   If password has only numbers (0123456789), then charset is 10
#                   If password has numbers (10) and lower case letters (26) then charset is 36 etc.
# 04/10/2022    Fixed bug in check_char_set function. used == instead of = to assign variable
#
# 
#from curses.ascii import isupper
from functools import total_ordering
from itertools import count
import re
import math
import string
keyspace = 0
countsp = 0
resalpha = 0
alphaupper = 0
alphalower = 0
charset = 0
isup = False
islow = False
isspace = False
isnumb = False
isspec = False



def get_key(password):
# Calculate the number of guesses to crack the password and password entropy
    global keyspace
    keyspace = charset**len(password)
    entropy_score = len(password)*math.log(charset) / math.log(2)
    return keyspace, entropy_score


def check_upper_chars(password):
# Count the number of UPPERCASE characters in password
    count = 0
    global isup
    for i in password:
        if i.isupper():
            isup = True
            count +=1
    return  count

def check_lower_chars(password):
# Count the number of lowercase characters in password
    count = 0
    global islow
    for i in password:
        if i.islower():
            islow = True
            count +=1
    return  count

def check_num(password):
# Count the number of digits in password
    count=0
    global isnumb
    for i in password:
       if i.isdigit():
           isnumb = True
           count +=1
    return count

def total_chars(password):
# Count the total number of ASCII characters in password
    total_ch=0
    for i in password:
        if i.isascii():
            total_ch +=1
    return total_ch


def advice():
    print ("Number of guesses to crack this password:",keyspace)
    print ("")
    print ("PASSWORD RECOMMENDATION")
    print ("-----------------------")
    print ("Using a passphrase with 3 or 4 uncommon words with a special character in the middle of a word")
    print ("These types of passwords cannot be brute-forced and are almost dictionary proof")
    print ("")


def space_count(password):
# Count the number of space characters in password
    count=0
    global isspace
    for i in range(0, len(password)):
        if password[i] == " ":
            isspace = True
            count += 1
    return count

def check_char_set(islow,isup,isspace,isnumb,isspec):
# Set charset. This depends on the characters used in the password
#
# Digits (0123456789) = 10
# Lowercase chars (abcdefghijklmnopqrstuvwxyz) = 26
# Uppercase chars = 26
# Special Characters (`~!@#$%^&*()-_=+[]\{}|;':",./<>? ) = 33 includng the space character
# 

    global charset
    if islow == True and isup == True and isspace == True and isnumb == True and isspec == True:
        charset = 95
        print ("Your password contains uppercase,lowercase characters, number(s) and special char(s)")
    if islow == True and isup == True and isspace == False and isnumb == True and isspec == True:
        charset = 95
        print ("Your password contains uppercase,lowercase characters, number(s) and special char(s)")
    if islow == True and isup == True and isspace == False and isnumb == True and isspec == False:
        charset = 62 # password has lowercase and uppercase chars only
        print ("Your password contains number(s), lowercase and uppercase characters")
    if islow == True and isup == False and isspace == False and isnumb == False and isspec == False:
        charset = 26 # password has lowercase chars
        print ("Your password contains lowercase characters")
    if islow == False and isup == True and isspace == False and isnumb == False and isspec == False:
        charset = 26 # password has uppercase chars 
        print ("Your password contains uppercase characters")
    if islow == False and isup == False and isspace == True and isnumb == False and isspec == True:
        charset = 33 # password has special chars
        print ("Your password contains number(s), special characters")
    if islow == False and isup == False and isspace == True and isnumb == True and isspec == True:
        charset = 43 # password has special chars and numbers
        print ("Your password contains special characters")
    if islow == True and isspace == True and isspec == True and isup == False and  isnumb == True:
        charset = 59 # password has lowercase chars, numbers and special chars
        print ("Your password contains number(s), special characters and lowercase characters")
    if islow == False and isspace == True and isspec == True and isup == True and  isnumb == True:
        charset = 59 # password has special chars, numbers and upper chars  
        print ("Your password contains number(s), special characters and upercase characters")
    if islow == True and isspace == False and isspec == False and isup == False and  isnumb == True:
        charset = 36 # password has numbers and lowercase chars  
        print ("Your password contains number(s) and lowercase characters")
    if islow == False and isspace == False and isspec == False and isup == True and  isnumb == True:
        charset = 36 # password has numbers and uppercase chars  
        print ("Your password contains number(s) and upercase characters")
    if islow == True and isspace == True and isspec == False and isup == False and  isnumb == False:
        charset = 59 # password has numbers and uppercase chars  
        print ("Your password contains number(s) and upercase characters")
    if islow == True and isspace == True and isspec == False and isup == False and  isnumb == True:
        charset = 62 # password has numbers and uppercase chars  
        print ("Your password contains number(s) and upercase characters")
    if islow == True and isspace == True and isspec == False and isup == True  and  isnumb == False:
        charset = 62 # password has numbers and uppercase chars  
        print ("Your password contains number(s) and upercase characters")
    return charset
       



def check_spec_chars(password):
# Count the total number of special characters in password
    count=0
    global isspec 
    spec_chars="`~!@#$%^&*()-_=+[]\\{}|;\':\",./<>?"
    for i in range(0,len(password)):
        if password[i] in spec_chars:
            isspec = True
            count += 1
    return count

def utf8len(password):
    return len(password.encode('utf-8'))

def main():
    password = input('Please enter password: ')
    print ('Your password:' , password) 
    print ("Total number of characters in your password :",total_chars(password))
 #   count_chars(password)
    print("Number of digits            : ",check_num(password))
    print("Number of spaces            : ",space_count(password))
    print("Number of Uppercase chars   : ",check_upper_chars(password))
    print("Number of Lowercase chars   : ",check_lower_chars(password))
    print("Number of Special chars     : ",check_spec_chars(password))
    print("islow =",islow)
    print("isup =",isup)
    print("isnumb =",isnumb)
    print("isspace =",isspace)
    print("isspec =",isspec)
    check_char_set(islow,isup,isspace,isnumb,isspec)
    print ("Character Set Size          : ", charset)
    print("")
    key_sp, ent_score = get_key(password)
    print ("Entropy score              : ",ent_score)
    if ent_score < 28:
        print ("### This is a VERY WEAK PASSWORD. You should be ashamed ###")
        print ("")
        print ("Passwords with an entropy score less that 25 can be easily hacked by brute force or dictionary attack ")
        advice()
    if ent_score > 27 and ent_score < 35:
        print ("### Your Password is WEAK. You can do better ###")
        print ("")
        print ("Passwords with an entropy score between 25 and 50 are considered weak and can be easily hacked by brute force or dictionary attack")
        advice()
    if ent_score > 34 and ent_score < 60:
        print ("### Your password is just OK. You can do better ###")
        print ("")
        print ("Passwords with an entropy score between 49 and 75 are considered OK.You are still at risk of being hacked by brute force or dictionary attacks")
        advice()
    if ent_score > 59 and ent_score < 127:
        print ("### This is a very strong password. Good work. ###")
        print ("")
        print ("Passwords with an entropy score between 50 and 00 are very strong and will be very difficult to hack")
        advice()
    if ent_score >  127:
        print ("### This is a an excellent password. Well done. ###")
        print ("")
        print ("Passwords with an entropy score greater than 100 are extremely strong and will be extremely difficult to hack")
        advice()
    input("Press Enter to close this window")

if __name__ == '__main__':
    main()


