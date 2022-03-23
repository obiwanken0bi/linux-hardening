import os, time
import subprocess
import json
from termcolor import colored

default = 'white'
success = 'green'
warning = 'red'


def menu():
    print("""
        __________________________________________
        |                                        |
        |                  MENU                  |
        |                                        |
        |         1. How to use this tool        |
        |         2. Launch audit                |
        |         3. Exit                        |
        |                                        |
        |________________________________________|
    """)

    user_input = input("Enter your choice: ")

    if user_input == '1': print("test test test"), time.sleep(1), menu()
    elif user_input == '2': audit(), time.sleep(1), menu()
    elif user_input == '3': print("\nBye !"), time.sleep(1), exit()
    else: print(colored("\nIncorrect input, please choose a valid number, asshole.", warning)), time.sleep(1), menu()


def exec_cmd(command):
    proc = subprocess.Popen(command, shell = True, stdin = None, stdout = subprocess.PIPE, stderr = subprocess.PIPE, encoding = 'utf8')
    (out, err) = proc.communicate(timeout=15)
    out = out.rstrip()  # .rstrip() removes training line
    err = err.rstrip()
    if err == "":
        print('Output: ' + out)
        return out
    else:
        # print('Error: '  + err)
        print('Output (err): '  + err)
        return err


def main():
    print("\nHello there!")
    time.sleep(1)
    menu()


def audit():
    print("")
    f = open('audit_list.json')
    audits = json.load(f)

    for audit in audits:
        id = audit["id"]
        cis = audit["cis"]
        title = audit["title"]
        audit_cmd = audit["audit"]
        expected = audit["expected"]
        fix_cmd = audit["remediation"]
        passed = False

        print("Auditing CIS: " + cis + "...")

        time.sleep(1)

        result = exec_cmd(audit_cmd)

        if expected in result:
            passed = True
            print(colored("[✓] " + title, success))
        else:
            print(colored("[X] " + title, warning))
        print("")
        time.sleep(0.2)

    print(colored("Audit completed!", success))


main()
