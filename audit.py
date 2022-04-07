import os, sys, time
import subprocess
import json
from datetime import datetime
from wsgiref.simple_server import sys_version
from termcolor import colored
from mdutils.mdutils import MdUtils
from obiwan import obiwan


default = 'white'
success = 'green'
info = 'yellow'
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
    elif user_input == '3': print("\nBye !\n"), wait(1), exit()
    else: print(colored("\nIncorrect input, please choose a valid number.", info)), wait(1), menu()


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


def remediation_summary(fails, remaining_fails, audits):
    print("""
     _______________________
    |                       |
    |  Remediation summary  |
    |_______________________|
    """)
    wait(0.25)
    if len(remaining_fails) == 0:
        print(colored("Remediation completed!", success))
    else:
        print(colored("Some remediation attempt(s) failed: ", warning))
        for fail_id in remaining_fails:
            for entry in audits:
                if entry['id'] == fail_id:
                    print("[CIS ", entry['cis'], "] ", entry['title'])
                    break

    success_fixes = list(set(fails) - set(remaining_fails))
    if success_fixes:
        print(colored("\nSuccessfully fixed: " + str(success_fixes), success))

    input("\nPress any key to return to menu")
    clear()
    menu()


def fix_all(fails):
    f = open('audit_list.json')
    audits = json.load(f)

    remaining_fails = fails

    for fail_id in fails:
        for entry in audits:
            if entry['id'] == fail_id:
                print("\nVulnerability: " + entry['title'])
                if (entry['remediation'] != ""):
                    # fix_result = exec_cmd(entry['remediation'] + " -y")   # UNCOMMENT THIS ONLY IN A VM
                    wait(0.2)
                    dots("Checking if remediation worked", 0.25)

                    check_result = exec_cmd(entry['audit'])
                    if entry['expected'] in check_result:
                        remaining_fails.remove(fail_id)
                        print(colored("[✓] Vuln fixed - " + entry['title'], success))
                    else:
                        print(colored("[✗] Remediation didn't work - " + entry['title'], warning))
                else:
                    print(colored("[✗] No remediation found - " + entry['title'], info))
    
    f.close()
    wait(0.5)
    remediation_summary(fails, remaining_fails, audits)


def fix_one_by_one(fails):
    print("In progress...")
    wait(0.25)

    f = open('audit_list.json')
    audits = json.load(f)

    remaining_fails = fails

    for fail_id in fails:
        for entry in audits:
            if entry['id'] == fail_id:
                print("\nVulnerability: " + entry['title'])
                if (entry['remediation'] != ""):
                    user_input = ""
                    while user_input.lower() not in ("yes", "no"):
                        user_input = input("Do you want to fix this vulnerability? [yes|no] ")
                        if user_input.lower() == "yes":
                            wait(0.2)
                            # fix_result = exec_cmd(entry['remediation'] + " -y")   # UNCOMMENT THIS ONLY IN A VM
                            dots("Checking if remediation worked", 0.25)
                            check_result = exec_cmd(entry['audit'])
                            if entry['expected'] in check_result:
                                remaining_fails.remove(fail_id)
                                print(colored("[✓] Vuln fixed - " + entry['title'], success))
                            else:
                                print(colored("[✗] Remediation didn't work - " + entry['title'], warning))
                        elif user_input.lower() == "no":
                            wait(0.2)
                            print(colored("[✗] Remediation refused by user - " + entry['title'], info))
                            break
                        else:
                            print(colored("Please enter 'yes' or 'no', is that so difficult?\n", info))
                else:
                    print(colored("[✗] No remediation found - " + entry['title'], info))
    f.close()
    wait(0.5)
    remediation_summary(fails, remaining_fails, audits)


def remediation(fails):
    if len(fails) == 0:
        menu()
    else:
        print("\n" + str(len(fails)) + " vulnerabilies found by audit.")
        print("""
__________________________________________
|                                        |
|              REMEDIATION               |
|                                        |
|       1. Fix all vulnerabilities       |
|       2. Fix one by one                |
|       3. Do nothing                    |
|                                        |
|________________________________________|
        """)

        user_input = input("Enter your choice: ")

        if user_input == '1': clear(), fix_all(fails)
        elif user_input == '2': clear(), fix_one_by_one(fails)
        elif user_input == '3': print("\nReturning to menu..."), wait(0.25), menu()
        else: print(colored("\nIncorrect input, please choose a valid number.", info)), wait(1), remediation(fails)


# audit_report = [
#                 audit_date,
#                 rule_report1,
#                 rule_report2,
#                 ...
#                ]
# rule_report = [id, cis, title, audit_cmd, expected, fix_cmd, passed]

def save_to_txt(fails, audit_report):
    filename = "audit_report_" + str(audit_report[0])
    
    with open(filename + ".txt", 'w') as sf:
        sf.write("Audit date: " + str(audit_report[0]) + "\n\n")
        audit_report.pop(0)
        for rule_report in audit_report:
            if rule_report[6] == True:
                sf.write("    [PASS] " + str(rule_report[1]) + " - " + str(rule_report[2]) + "\n")
            else:
                sf.write("/!\ [FAIL] " + str(rule_report[1]) + " - " + str(rule_report[2]) + "\n")
    sf.close()

    print("Filename: " + filename + ".txt")
    print(colored("File saved in current directory.", success))
    wait(0.5)
    remediation(fails)


def save_to_md(fails, audit_report):
    print("In progress...")
    print("File saved in txt for now.")
    # mdFile = MdUtils(file_name=filename, title='Audit report')
    # code
    # mdFile.create_md_file()
    wait(0.5)
    remediation(fails)


def save_to_csv(fails, audit_report):
    print("TODO")
    print("File saved in txt for now.")
    # print("Filename: " + filename + ".txt")
    wait(0.5)
    remediation(fails)


def save_to_pdf(fails, audit_report):
    print("TODO")
    print("File saved in txt for now.")
    # print("Filename: " + filename + ".txt")
    wait(0.5)
    remediation(fails)


def save_results(fails, audit_report):
    print("""
__________________________________________
|                                        |
|              SAVE RESULTS              |
|                                        |
|         1. Save to txt file            |
|         2. Save to md file             |
|         3. Save to csv file            |
|         4. Save to pdf file            |
|         5. Cancel                      |
|                                        |
|________________________________________|
    """)

    user_input = input("Enter your choice: ")

    if user_input == '1': clear(), save_to_txt(fails, audit_report)
    elif user_input == '2': clear(), save_to_md(fails, audit_report)
    elif user_input == '3': clear(), save_to_csv(fails, audit_report)
    elif user_input == '4': clear(), save_to_pdf(fails, audit_report)
    elif user_input == '5': print("\nCancelled !"), wait(0.25), remediation(fails)
    else: print(colored("\nIncorrect input, please choose a valid number.", info)), wait(1), save_results(fails, audit_report)


def display_audit_summary(ok, nok, fails, audit_report):
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
    print(colored("Pass : " + str(ok), success))
    print(colored("Fail : " + str(nok) + "\n", warning))

    user_input = ""
    while user_input.lower() not in ("yes", "no"):
        user_input = input("Do you want to save results to a file? [yes|no] ")
        if user_input.lower() == "yes":
            clear()
            wait(0.2)
            save_results(fails, audit_report)
        elif user_input.lower() == "no":
            # os.remove(filename + ".txt")
            wait(0.25)
            remediation(fails)
        else:
        	print(colored("Please enter 'yes' or 'no', is that so difficult?\n", info))


def audit():
    print("")
    f = open('audit_list.json')
    audits = json.load(f)

    nb_audits = len(audits)
    print("Nombre de règles: " + str(nb_audits) + "\n")

    ok = 0
    nok = 0

    fails = []
    audit_report = []

    audit_date = datetime.today().strftime('%Y-%m-%d-%H%M%S')
    # filename = "audit_summary_" + audit_date

    # with open(filename + ".txt", 'w') as sf:
    #     sf.write("Audit date: " + audit_date + "\n\n\n")
    #     remaining_audits = nb_audits

    #     for audit in audits:
    #         id = audit["id"]
    #         cis = audit["cis"]
    #         title = audit["title"]
    #         audit_cmd = audit["audit"]
    #         expected = audit["expected"]
    #         fix_cmd = audit["remediation"]
    #         passed = False

    #         dots("Auditing CIS: " + cis, 0.2)

    #         result = exec_cmd(audit_cmd)

    #         if expected in result:
    #             passed = True
    #             ok += 1
    #             print(colored("[✓] " + title, success))
    #             sf.write("    [PASS] " + cis + " - " + title + "\n")
    #         else:
    #             nok += 1
    #             print(colored("[✗] " + title, warning))
    #             sf.write("/!\ [FAIL] " + cis + " - " + title + "\n")
    #             fails.append(id)
    #         remaining_audits -= 1
    #         print("Remaining audits :" + str(remaining_audits) + "\n")
    #         wait(0.05)

    #     input(colored("Audit completed! Press any key to display summary", success))
    #     clear()

    # sf.close()
    # display_audit_summary(ok, nok, filename, fails)

    # ##############################################

    audit_report.append(audit_date)
    remaining_audits = nb_audits

    for audit in audits:
        id = audit["id"]
        cis = audit["cis"]
        title = audit["title"]
        audit_cmd = audit["audit"]
        expected = audit["expected"]
        fix_cmd = audit["remediation"]
        passed = False

        dots("Auditing CIS: " + cis, 0.2)

        result = exec_cmd(audit_cmd)

        if expected in result:
            passed = True
            ok += 1
            print(colored("[✓] " + title, success))
        else:
            nok += 1
            print(colored("[✗] " + title, warning))
            fails.append(id)
        remaining_audits -= 1
        rule_report = [id, cis, title, audit_cmd, expected, fix_cmd, passed]
        audit_report.append(rule_report)
        print("Remaining rules to audit :" + str(remaining_audits) + "\n")
        wait(0.05)

    input(colored("Audit completed! Press any key to display summary", success))
    clear()
    display_audit_summary(ok, nok, fails, audit_report)

    # ##############################################


if __name__ == '__main__':
    try:
        if sys.version_info[0] < 3:
            version = ".".join(map(str, sys.version_info[:3]))
            print("\nYou are using Python " + version)
            print(colored("\nPlease use Python 3 !\n", warning))
            print("Exiting...")
            wait(0.5)
            quit()
        else:
            main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user... Yes, you.")

