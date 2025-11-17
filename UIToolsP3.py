import os
import struct
# import netaddr
import json
import re
from getpass import getpass
# from openpyxl import load_workbook
from datetime import datetime


logName = ''
dirPath = os.path.dirname(os.path.abspath(__file__))


def getFromNumberdList(inlist, msg="Selection: "):
    # Takes in a list, prints out with numbers, asks user for selection, returns selection, can optionally take a message to print to the user (defaults to "Selection: ")
    options = {}
    c = 1
    for x in inlist:
        # Build dictionary of the from number: <item in list>
        options[c] = x
        print(str(c) + " - " + str(x))
        c += 1

    ri = input("\n" + msg)
    try:
        return options.get(int(ri))
    except:
        # If the inputed selection doesn't work inform user and try again
        print("Invalid input, please try again\n")


def getBool(msg="Yes or No: ", trueA=['Yes', 'yes', 'Y', 'y', 'True', 'true', 'T', 't'],
            falseA=['No', 'no', 'N', 'n', 'False', 'false', 'F', 'f']):
    # Returns a boolean from user input, optionally takes a message to print as well as lists of accepted inputs for true and false
    ans = input(msg)
    if ans in trueA:
        return True
    elif ans in falseA:
        return False
    else:
        print("Invalid answer")
        return getBool(msg, trueA, falseA)


def waitForInput(msg='Hit enter/return to continue...'):
    # Waits for any input before continuing.
    input(msg)


def printHeader(text, tWidth=80, fWidth=100, file=None):
    # Prints a simple header spanning the width
    print('{:-^{c}}'.format('-', c=tWidth))
    print('{:^{c}}'.format(text, c=tWidth))
    print('{:-^{c}}'.format('-', c=tWidth))

    if file:
        file.write('{:-^{c}}'.format('-', c=fWidth) + '\n')
        file.write('{:^{c}}'.format(text, c=fWidth) + '\n')
        file.write('{:-^{c}}'.format('-', c=fWidth) + '\n')


def printSubHeader(text, tWidth=80, fWidth=100, file=None):
    # Prints a simple subHeader spanning the width
    print('{:-^{c}}'.format(text, c=tWidth))

    if file:
        file.write('\n' + '{:-^{c}}'.format(text, c=fWidth) + '\n')


# def getXlsxFile(msg='Xlsx file name?: ', projectDir=None):
#     # Gets a valid xlsx file
#     ans = input(msg)
#     if projectDir is not None:
#         filePath = projectDir + '/' + ans
#     else:
#         filePath = ans
#     try:
#         wb = load_workbook(filePath)
#         print('Found file')
#         addLog('Opened file '+filePath)
#         return wb
#     except FileNotFoundError:
#         print('File not found ' + filePath)
#         addLog('Could not find file ' + filePath)
#         return getXlsxFile(msg, projectDir=projectDir)

def getJSONFile(msg='JSON file name?: ', path=""):
    # Gets a valid JSON file
    ans = input(msg)
    try:
        with open(path+ans) as jf:
            jsonData = json.load(jf)
            print('Found JSON')
            return jsonData
    except:
        print('Did not find JSON')
        return getJSONFile(msg, path)

def getFile(msg='File Path: ', path=''):
    ans = input(msg)
    try:
        with open(path+ans) as f:
            print("Found File")
            return ans
    except:
        print('Did not find File')
        return getFile(msg, path)

def getIP(msg="IP: ", iptype='Network', inIP=None):
    # Returns a properly formated IP address from user input
    ip = input(msg)
    try:
        if iptype == 'Network':
            nodeIP = netaddr.IPNetwork(ip)
            return ip
        elif iptype == 'Address':
            nodeIP = netaddr.IPAddress(ip)
            return ip
        elif iptype == 'Mask':
            nodeIP = netaddr.IPNetwork(inIP + '/' + ip)
            return nodeIP.netmask
    except netaddr.core.AddrFormatError:
        print('Invalid IP and/or Mask')
        addLog('Invalid IP and/or Mask ' + ip)
        return getIP(msg)


def getEmail(msg="Email Address: "):
    # Gets a valid email
    email = input(msg)
    if re.search('^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$', email):
        return email
    else:
        print('Invalid Email')
        return getEmail(msg)


def getPassword(msg="Password: "):
    return getpass(prompt=msg)


def getListNums(msg='Enter a list of numbers seperated by a space: '):
    ans = input(msg).split()
    out = []
    for num in ans:
        try:
            out.append(int(num))
        except ValueError:
            print('Invalid Number')
            return getListNums(msg)
    return out


class Menu:
    def __init__(self, name, menuOptions=None, print_func=None):
        self.name = name
        self.menuOptions = menuOptions
        self.print_func = print_func

    def show(self):
        printHeader(self.name)
        if self.print_func is not None:
            self.print_func()
        if self.menuOptions is not None:
            actualMenuOptions = self.menuOptions
            selection = self.menuOptions.get(getFromNumberdList(self.menuOptions.keys()))
            if selection == 'Back':
                return
            elif selection == 'Quit':
                quit()
            elif isinstance(selection, Menu):
                selection.show()
                self.show()
            else:
                selection()
                waitForInput()
                self.show()
