import os, sys, time
import subprocess
import json
from datetime import datetime
from wsgiref.simple_server import sys_version
from termcolor import colored
from obiwan import obiwan


default = 'white'
success = 'green'
warning = 'red'


def clear():
    os.system("clear")


def wait(s):
    time.sleep(s)


def dots(string, duration):
    s = '.'
    sys.stdout.write(string)
    t_end = time.time() + duration
    while time.time() < t_end:
        sys.stdout.write( s )
        sys.stdout.flush()
        wait(0.025)
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

    if user_input == '1': clear(), print("\nNothing for now"), wait(1), menu()
    elif user_input == '2': clear(), audit(), wait(1), menu()
    elif user_input == '3': print("\nBye !"), wait(1), exit()
    else: print(colored("\nIncorrect input, please choose a valid number.", warning)), wait(1), menu()


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
    obiwan()
    wait(1)
    menu()


def save_to_txt(filename):
    print(colored("File saved in current directory.", success))
    print("Filename: " + filename + ".txt")
    wait(1)
    menu()


def save_to_csv(filename):
    print("TODO")
    print("File saved in txt for now.")
    print("Filename: " + filename + ".txt")
    wait(1)
    menu()


def save_to_pdf(filename):
    print("TODO")
    print("File saved in txt for now.")
    print("Filename: " + filename + ".txt")
    wait(1)
    menu()


def save_results(filename):
    print("""
        __________________________________________
        |                                        |
        |              SAVE RESULTS              |
        |                                        |
        |         1. Save to txt file            |
        |         2. Save to csv file            |
        |         3. Save to pdf file            |
        |         4. Cancel                      |
        |                                        |
        |________________________________________|
    """)

    user_input = input("Enter your choice: ")

    if user_input == '1': clear(), save_to_txt(filename), wait(0.25), menu()
    elif user_input == '2': clear(), save_to_csv(filename), wait(0.25), menu()
    elif user_input == '3': clear(), save_to_pdf(filename), wait(0.25), menu()
    elif user_input == '4': print("\nCancelled !"), wait(0.25), os.remove(filename + ".txt")
    else: print(colored("\nIncorrect input, please choose a valid number.", warning)), wait(1), save_results()


def display_audit_summary(ok, nok, filename):
    print("""
         ___________
        |           |
        |   Audit   |
        |  summary  |
        |___________|
           ||
    (\__/) ||
    (•ㅅ•) ||
    /     づ
    """)
    wait(0.5)
    print(colored("    Pass :    " + str(ok), success))
    print(colored("    Fail :    " + str(nok) + "\n", warning))

    user_input = ""
    while user_input.lower() not in ("yes", "no"):
        user_input = input("Do you want to save results to a file? [yes|no] ")
        if user_input.lower() == "yes":
            clear()
            wait(0.2)
            save_results(filename)
        elif user_input.lower() == "no":
            os.remove(filename + ".txt")
            dots("Returning to menu", 0.25)
            menu()
        else:
        	print(colored("Please enter 'yes' or 'no', is that so difficult?\n", warning))


def audit():
    print("")
    f = open('audit_list.json')
    audits = json.load(f)

    ok = 0
    nok = 0

    filename = "audit_summary_" + datetime.today().strftime('%Y-%m-%d-%H%M%S')

    with open(filename + ".txt", 'w') as sf:

        for audit in audits:
            id = audit["id"]
            cis = audit["cis"]
            title = audit["title"]
            audit_cmd = audit["audit"]
            expected = audit["expected"]
            fix_cmd = audit["remediation"]
            passed = False

            dots("Auditing CIS: " + cis, 0.25)

            result = exec_cmd(audit_cmd)

            if expected in result:
                passed = True
                ok += 1
                print(colored("[✓] " + title, success))
                sf.write("    [PASS] " + cis + " - " + title + "\n")
            else:
                nok += 1
                print(colored("[✗] " + title, warning))
                sf.write("/!\ [FAIL] " + cis + " - " + title + "\n")
            print("")
            wait(0.05)

        input(colored("Audit completed! Press any key to display summary", success))
        clear()

    sf.close()
    display_audit_summary(ok, nok, filename)


if __name__ == '__main__':
    if sys.version_info[0] < 3:
        version = ".".join(map(str, sys.version_info[:3]))
        print("\nYou are using Python " + version)
        print(colored("\nPlease use Python 3 !\n", warning))
        print("Exiting...")
        wait(0.5)
        quit()
    else:
        main()
