import os, sys, time
import subprocess
import json
from wsgiref.simple_server import sys_version
from termcolor import colored

default = 'white'
success = 'green'
warning = 'red'


def clear():
    os.system("clear")


def wait(s):
    time.sleep(s)


def dots(string):
    s = '.'
    sys.stdout.write(string)
    t_end = time.time() + 0.25
    while time.time() < t_end:
        sys.stdout.write( s )
        sys.stdout.flush()
        time.sleep(0.025)
    print("")


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

    if user_input == '1': print("\nRien"), time.sleep(1), menu()
    elif user_input == '2': clear(), audit(), time.sleep(1), menu()
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
    clear()
    print("\nHello there!")
    time.sleep(0.5)
    menu()


def display_audit_results(ok, nok):
    print("""
         ___________
        |           |
        |   Audit   |
        |  results  |
        |___________|
           ||
    (\__/) ||
    (•ㅅ•) ||
    /     づ
    """)
    time.sleep(0.5)
    print(colored("    Pass :    " + str(ok), success))
    print(colored("    Fail :    " + str(nok) + "\n", warning))
    print("Do you want to save results? [Y|n]")
    # txt ? md ? csv ?


def audit():
    print("")
    f = open('audit_list.json')
    audits = json.load(f)

    ok = 0
    nok = 0

    for audit in audits:
        id = audit["id"]
        cis = audit["cis"]
        title = audit["title"]
        audit_cmd = audit["audit"]
        expected = audit["expected"]
        fix_cmd = audit["remediation"]
        passed = False

        dots("Auditing CIS: " + cis)

        result = exec_cmd(audit_cmd)

        if expected in result:
            passed = True
            ok += 1
            print(colored("[✓] " + title, success))
        else:
            nok += 1
            print(colored("[X] " + title, warning))
        print("")
        time.sleep(0.05)

    input(colored("Audit completed! Press a key to display results", success))
    clear()

    display_audit_results(ok, nok)


if __name__ == '__main__':
    if sys.version_info[0] < 3:
        version = ".".join(map(str, sys.version_info[:3]))
        print("\nYou are using Python " + version)
        print(colored("\nPlease use Python 3 !\n", warning))
        print("Exiting...")
        time.sleep(0.5)
        quit()
    else:
        main()
