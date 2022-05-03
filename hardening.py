# Librairies import
import os, sys, time, subprocess
import json, csv
import random
import threading, queue
from datetime import datetime
from termcolor import colored
from mdutils.mdutils import MdUtils
from obiwan import obiwan
from title import title


# Colors for termcolor
default = 'white'
success = 'green'
info = 'yellow'
warning = 'red'


#---------------------------------------------------------------------#
#     Usefull little functions that improve design/UX/refactoring     #
#---------------------------------------------------------------------#

# Clear screen
def clear():
    os.system("clear")


# Wait for 's' seconds (param can be an integer or a float)
def wait(s):
    time.sleep(s)


# Checks if user has privileged rights
def is_root():
    return os.geteuid() == 0


# Prints 'string' then an amount of dots one by one for 'duration' seconds
def dots(string, duration):
    s = '.'
    sys.stdout.write(string)
    t_end = time.time() + duration
    while time.time() < t_end:
        sys.stdout.write( s )
        sys.stdout.flush()
        wait(0.025)
    print("")


# Prints 'string' characters one by one, each one separated by 'duration' seconds
def delay_print(string, duration):
    for char in string:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(duration)


# Prints an increasing counter from 1 to 'int', each one separated by 'delay' seconds
def increasing_counter(int, delay):
    for i in range(int):
        print('\r', str(i), end = '')
        time.sleep(delay)


# Prints an animated loading string
def animated_loading(string):
    chars = ["⢿", "⣻", "⣽", "⣾", "⣷", "⣯", "⣟", "⡿"]
    for char in chars:
        sys.stdout.write('\r' + " " + char + string)
        time.sleep(.1)
        sys.stdout.flush()


# Executes a shell command and returns the output or error
def exec_cmd(command):
    proc = subprocess.Popen(command, shell = True, stdin = None, stdout = subprocess.PIPE, stderr = subprocess.PIPE, encoding = 'utf8')
    (out, err) = proc.communicate(timeout=15)
    out = out.rstrip()  # .rstrip() removes training line
    err = err.rstrip()
    if err == "":
        return out
    else:
        return err


# Switches temporarily CLI language to english (it reverts back when the tool's process ends)
def switch_to_en():
    # out = exec_cmd("env |egrep -e 'LANGUAGE|LC_ALL|LANG='")    
    cmd1 = os.environ["LANG"] = "en_US.UTF-8"
    exec_cmd(cmd1)
    cmd2 = os.environ["LC_ALL"] = "en_US.UTF-8"
    exec_cmd(cmd2)
    cmd3 = os.environ["LANGUAGE"] = "en_US.UTF-8"
    exec_cmd(cmd3)


#----------------------------------------------------------------------#
#                            Main functions                            #
#----------------------------------------------------------------------#

def main():
    clear()
    delay_print(obiwan, 0.0001)
    delay_print(title, 0.0005)
    wait(0.1)
    menu()


# Prints the main menu
def menu():
    print("""
 ╔═════════════════════════════════════╗
 ║                                     ║
 ║                 MENU                ║
 ║                                     ║
 ║       1. How to use this tool       ║
 ║       2. Launch audit               ║
 ║       3. Exit                       ║
 ║                                     ║
 ╚═════════════════════════════════════╝""")
    print("")

    user_input = input(" Enter your choice: ")

    if user_input == '1': clear(), print("\nNothing for now"), wait(1), menu()
    elif user_input == '2': clear(), audit(), wait(1), menu()
    elif user_input == '3': print("\nBye !\n"), wait(1), exit()
    else: print(colored("\nIncorrect input, please choose a valid number.", info)), wait(0.5), menu()


# Performs audit on system from JSON rules list
# Returns number of passed and fails, an array of fails ids and an array usefull for the report
def audit():
    f = open('audit_list.json')
    audits = json.load(f)

    nb_audits = len(audits)
    print("\n " + str(nb_audits) + " rules to check\n")
    wait(0.5)

    # Initialization of successes/fails counters, and usefull report arrays
    ok = 0
    nok = 0
    fails = []
    audit_report = []
    remaining_fails = []

    audit_date = datetime.today().strftime('%Y-%m-%d-%H%M%S')
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

        # dots("Auditing CIS: " + cis, 0.1)
        delay_print("Auditing CIS: " + cis + "...\n", 0.005)

        result = exec_cmd(audit_cmd)

        if expected in result:
            passed = True
            ok += 1
            print(colored("[✓] " + title + "\n", success))
        else:
            nok += 1
            print(colored("[✗] " + title + "\n", warning))
            fails.append(id)
        remaining_audits -= 1
        rule_report = [id, cis, title, audit_cmd, expected, fix_cmd, passed]
        audit_report.append(rule_report)
        wait(0.05)

    input(colored("""
 ┌─────────────────────────────────────────────────┐
 │ Audit completed! Press Enter to display summary │
 └─────────────────────────────────────────────────┘
""", default))
    clear()
    display_audit_summary(ok, nok, fails, remaining_fails, audits, audit_report)


# Displays the audit summary and asks the user if he/she wants to save a report
def display_audit_summary(ok, nok, fails, remaining_fails, audits, audit_report):
    print("""
 ╔═════════════════════════════════════╗
 ║                                     ║""")
    delay_print(" ║            AUDIT SUMMARY            ║", 0.01)
    print("\n ║                                     ║")

    for i in range(ok + 1):
        if i < 10:
            print('\r ║       Pass : ' + str(i) + '                      ║', end = '')
        elif i < 100:
            print('\r ║       Pass : ' + str(i) + '                     ║', end = '')
        else:
            print('\r ║       Pass : ' + str(i) + '                    ║', end = '')
        time.sleep(0.05)
    print("")

    for i in range(nok + 1):
        if i < 10:
            print('\r ║       Fail : ' + str(i) + '                      ║', end = '')
        elif i < 100:
            print('\r ║       Fail : ' + str(i) + '                     ║', end = '')
        else:
            print('\r ║       Fail : ' + str(i) + '                    ║', end = '')
        time.sleep(0.05)
    print("""
 ║                                     ║
 ╚═════════════════════════════════════╝""")
    wait(0.5)
    remediation(fails, remaining_fails, audits, audit_report)


# Menu asking the user if he/she wants to fix the vulnerabilities found by the audit
def remediation(fails, remaining_fails, audits, audit_report):
    if len(fails) == 0:
        save_results(fails, remaining_fails, [], audit_report)
    else:
        print("\nWe recommend to apply as many fixes as possible. \n\nYou can fix all vulnerabilities at once with the first option, \nbut if you prefer to choose which fix you want to apply, choose the second option.\n")
        wait(0.25)
        print("""
 ╔═════════════════════════════════════╗
 ║                                     ║
 ║             REMEDIATION             ║
 ║                                     ║
 ║      1. Fix all vulnerabilities     ║
 ║      2. Fix one by one              ║
 ║      3. Do nothing                  ║
 ║                                     ║
 ╚═════════════════════════════════════╝""")
        print("")

        user_input = input("Enter your choice: ")

        if user_input == '1': clear(), fix_all(fails, audit_report)
        elif user_input == '2': clear(), fix_one_by_one(fails, audit_report)
        elif user_input == '3': clear(), save_results(fails, remaining_fails, [], audit_report)
        else: print(colored("\nIncorrect input, please choose a valid number.", info)), wait(0.5), remediation(fails, remaining_fails, audits, audit_report)


# Executes fix command and checks if fix worked
def fix_and_check(entry, q):
    wait(0.2)
    fix_result = exec_cmd(entry['remediation'] + " -y")
    if "invalid option -- 'y'" in fix_result:
        fix_result = exec_cmd(entry['remediation'])
    check_result = exec_cmd(entry['audit'])
    q.put([fix_result, check_result])   # Sends function's results to thread's queue


# Tries to fix all the vulnerabilities found
def fix_all(fails, audit_report):
    f = open('audit_list.json')
    audits = json.load(f)

    remaining_fails = fails.copy()

    print("""
 ┌─────────────────────────┐
 │ Fix all vulnerabilities │
 └─────────────────────────┘""")

    for fail_id in fails:
        for entry in audits:
            if entry['id'] == fail_id:
                print(colored("\n\nRule: " + entry['title'] + " (CIS " + entry['cis'] + ")\n", attrs=['bold']))

                if (entry['remediation'] != ""):
                    wait(0.1)

                    q = queue.Queue()
                    the_process = threading.Thread(name='process', target=fix_and_check, args=(entry, q))
                    the_process.start()

                    while the_process.is_alive():
                        animated_loading(" Applying remediation...")
                    
                    results = q.get()
                    fix_result = results[0]
                    check_result = results[1]
                    
                    if entry['expected'] in check_result:
                        remaining_fails.remove(fail_id)
                        for rule_report in audit_report:
                            if rule_report[0] == entry['id']:
                                rule_report[6] = True   # passed = True
                                break
                        print(colored("\n\n [✓] Vuln fixed", success))
                    else:
                        print("\n\n Error: " + fix_result)
                        print(colored("\n [✗] Remediation didn't work", warning))
                    wait(0.2)
                else:
                    print(colored("[✗] No remediation found", info))
    f.close()
    wait(0.5)
    remediation_summary(fails, remaining_fails, audits, audit_report)


# Tries to fix each vulnerability found, asking the user for each one
def fix_one_by_one(fails, audit_report):
    f = open('audit_list.json')
    audits = json.load(f)

    remaining_fails = fails.copy()

    print("""
 ┌─────────────────────────────────────┐
 │ Choose which vulnerabilities to fix │
 └─────────────────────────────────────┘""")

    for fail_id in fails:
        for entry in audits:
            if entry['id'] == fail_id:
                print(colored("\n\nRule: " + entry['title'] + " (CIS " + entry['cis'] + ")", attrs=['bold']))

                if (entry['remediation'] != ""):
                    user_input = ""
                    while user_input.lower() not in ("y", "n"):
                        user_input = input("\n ↳ Do you want to fix this vulnerability? [y|n] ")
                        print("")
                        if user_input.lower() == "y":
                            wait(0.1)

                            q = queue.Queue()
                            the_process = threading.Thread(name='process', target=fix_and_check, args=(entry, q))
                            the_process.start()

                            while the_process.is_alive():
                                animated_loading(" Applying remediation...")

                            results = q.get()
                            fix_result = results[0]
                            check_result = results[1]
                            
                            if entry['expected'] in check_result:
                                remaining_fails.remove(fail_id)
                                for rule_report in audit_report:
                                    if rule_report[0] == entry['id']:
                                        rule_report[6] = True   # passed = True
                                        break
                                print(colored("\n\n [✓] Vuln fixed", success))
                            else:
                                print("\n\n Error: " + fix_result)
                                print(colored("\n [✗] Remediation didn't work", warning))
                            wait(0.2)

                        elif user_input.lower() == "n":
                            wait(0.2)
                            print(colored(" [✗] Remediation refused by user\n", info))
                            break
                        else:
                            print(colored(" Please enter 'y' or 'n', is that so difficult?\n", info))
                else:
                    print(colored(" [✗] No remediation found\n", info))
    f.close()
    wait(0.5)
    remediation_summary(fails, remaining_fails, audits, audit_report)


# Prints the remediation summary
def remediation_summary(fails, remaining_fails, audits, audit_report):
    print("""
 ┌─────────────────────┐
 │ REMEDIATION SUMMARY │
 └─────────────────────┘
""")
    wait(0.25)
    if len(remaining_fails) == 0:
        print(colored("Remediation completed!", success))
    else:
        print(colored("Remediation failed on the following rules: ", warning))
        for fail_id in remaining_fails:     # Listing all remaining fails
            for entry in audits:
                if entry['id'] == fail_id:
                    print("- " + entry['title'] + " (CIS " + entry['cis'] + ")")
                    break

    success_fixes = list(set(fails) - set(remaining_fails))
    if success_fixes:
        print(colored("\nSuccessfully fixed: ", success))
        for fixed_id in success_fixes:      # Listing all successful fixes
            for entry in audits:
                if entry['id'] == fixed_id:
                    print("- " + entry['title'] + " (CIS " + entry['cis'] + ")")
                    break

    wait(0.5)
    print("")
    user_input = ""
    while user_input.lower() not in ("y", "n"):
        user_input = input("""
 ┌──────────────────────────────────────────────┐
 │ Do you want to save results to a file? [y|n] │
 └──────────────────────────────────────────────┘""")
        if user_input.lower() == "y":
            clear()
            wait(0.2)
            save_results(fails, remaining_fails, success_fixes, audit_report)
        elif user_input.lower() == "n":
            wait(0.25)
            clear()
            menu()
        else:
        	print(colored(" Please enter 'y' (yes) or 'n' (no), is that so difficult?\n", info))


# Menu for saving audit results in different formats
def save_results(fails, remaining_fails, success_fixes, audit_report):
    print("""
 ╔═════════════════════════════════════╗
 ║                                     ║
 ║             SAVE RESULTS            ║
 ║                                     ║
 ║       1. Save to txt file           ║
 ║       2. Save to md file            ║
 ║       3. Save to csv file           ║
 ║       4. Save to all formats        ║
 ║       5. Cancel                     ║
 ║                                     ║
 ╚═════════════════════════════════════╝\n""")

    user_input = input("Enter your choice: ")
    print("")

    if user_input == '1': save_to_txt(fails, remaining_fails, success_fixes, audit_report, False)
    elif user_input == '2': save_to_md(fails, remaining_fails, success_fixes, audit_report, False)
    elif user_input == '3': save_to_csv(fails, remaining_fails, success_fixes, audit_report, False)
    # elif user_input == '4': save_to_pdf(fails, remaining_fails, success_fixes, audit_report, False)
    elif user_input == '4': save_to_all_formats(fails, remaining_fails, success_fixes, audit_report)
    elif user_input == '5': print("\nCancelled !"), wait(0.25), clear(), menu()
    else: print(colored("\nIncorrect input, please choose a valid number.", info)), wait(0.5), save_results(fails, remaining_fails, success_fixes, audit_report)


# Memo for 'audit_report' and 'rule_report' formats :
# audit_report = [audit_date, rule_report1, rule_report2, ...]
# rule_report = [id, cis, title, audit_cmd, expected, fix_cmd, passed]

# Saves the report to a txt file
def save_to_txt(fails, remaining_fails, success_fixes, audit_report, all):
    audit_date = audit_report[0]
    filename = "audit_report_" + str(audit_date)
    
    with open(filename + ".txt", 'w') as sf:
        sf.write("Audit date: " + str(audit_date) + "\n\n")
        audit_report.pop(0)
        sf.write("Vulnerabilities found by initial audit: " + str(len(fails)) + "\n")
        sf.write("Successfully fixed: " + str(len(success_fixes)) + "\n")
        sf.write("Remaining vulnerabilities after remediation attempt: " + str(len(remaining_fails)) + "\n\n")
        for rule_report in audit_report:
            if rule_report[6] == True:
                if rule_report[0] in fails:
                    sf.write("   [FIXED] " + str(rule_report[1]) + " - " + str(rule_report[2]) + "\n")
                else:
                    sf.write("    [PASS] " + str(rule_report[1]) + " - " + str(rule_report[2]) + "\n")
            else:
                sf.write("/!\ [FAIL] " + str(rule_report[1]) + " - " + str(rule_report[2]) + "\n")
    sf.close()

    audit_report.insert(0, audit_date)
    print("Filename: " + filename + ".txt")
    print(colored("[✓] .txt file saved in current directory.\n", success))
    wait(0.5)

    if all == False:    # Check if user asked to save result in all formats
        input(colored("""
 ┌──────────────────────────────────────────┐
 │ Press Enter to finish and return to menu │
 └──────────────────────────────────────────┘""", default))
        clear()
        menu()


# Saves the report to a markdown file (a list & an array)
def save_to_md(fails, remaining_fails, success_fixes, audit_report, all):
    audit_date = audit_report[0]
    filename = "audit_report_" + str(audit_date)
    mdFile = MdUtils(file_name=filename, title='Audit report')
    # date = datetime.strptime(audit_date, '%d-%m-%Y %H:%M:%S')
    mdFile.new_paragraph("Audit date : " + str(audit_date))
    audit_report.pop(0)
    mdFile.new_paragraph("Vulnerabilities found by initial audit : " + str(len(fails)))
    mdFile.new_paragraph("Successfully fixed: " + str(len(success_fixes)))
    mdFile.new_paragraph("Remaining vulnerabilities after remediation attempt : " + str(len(remaining_fails)))
    mdFile.write('  \n\n')
    
    # Classic list
    for rule_report in audit_report:
        if rule_report[6] == True:
            if rule_report[0] in fails:
                mdFile.new_paragraph("[FIXED] " + str(rule_report[1]) + " - " + str(rule_report[2]), color='blue')
            else:
                mdFile.new_paragraph("[PASS] " + str(rule_report[1]) + " - " + str(rule_report[2]), color='green')
        else:
            mdFile.new_paragraph("[FAIL] " + str(rule_report[1]) + " - " + str(rule_report[2]), color='red')
    mdFile.write('  \n\n')

    # Array
    list_of_strings = ["CIS", "Rule", "Passed"]
    for rule_report in audit_report:
        if rule_report[6] == True:
            if rule_report[0] in fails:
                list_of_strings.extend([str(rule_report[1]), str(rule_report[2]), "**<font color='blue'>Yes (fixed)</font>**"])
            else:
                list_of_strings.extend([str(rule_report[1]), str(rule_report[2]), "**<font color='green'>Yes</font>**"])
        else:
            list_of_strings.extend([str(rule_report[1]), str(rule_report[2]), "**<font color='red'>No</font>**"])
    mdFile.new_line()
    mdFile.new_table(columns=3, rows=len(audit_report)+1, text=list_of_strings, text_align='left')
    
    mdFile.create_md_file()

    audit_report.insert(0, audit_date)
    print("Filename: " + filename + ".md")
    print(colored("[✓] .md file saved in current directory.\n", success))
    wait(0.5)

    if all == False:    # Check if user asked to save result in all formats
        input(colored("""
 ┌──────────────────────────────────────────┐
 │ Press Enter to finish and return to menu │
 └──────────────────────────────────────────┘""", default))
        clear()
        menu()


# Saves the report to a csv file
def save_to_csv(fails, remaining_fails, success_fixes, audit_report, all):
    audit_date = audit_report[0]
    filename = "audit_report_" + str(audit_date)
    audit_report.pop(0)

    headers = ['cis', 'title', 'passed']
    rows = []
    for rule_report in audit_report:
        row = [ rule_report[1], rule_report[2], rule_report[6] ]
        rows.append(row)
    with open(filename + '.csv', 'w') as f:
        write = csv.writer(f,delimiter=';')
        write.writerow(headers)
        write.writerows(rows)

    audit_report.insert(0, audit_date)
    print("Filename: " + filename + ".csv")
    print(colored("[✓] .csv file saved in current directory.\n", success))
    wait(0.5)
    
    if all == False:    # Check if user asked to save result in all formats
        input(colored("""
 ┌──────────────────────────────────────────┐
 │ Press Enter to finish and return to menu │
 └──────────────────────────────────────────┘""", default))
        clear()
        menu()


# TODO
# Saves the report to a pdf file
def save_to_pdf(fails, remaining_fails, success_fixes, audit_report, all):
    print("TODO")
    audit_date = audit_report[0]
    filename = "audit_report_" + str(audit_date)
    print("Filename: " + filename + ".pdf")
    wait(0.5)

    if all == False:    # Check if user asked to save result in all formats
        input(colored("""
 ┌──────────────────────────────────────────┐
 │ Press Enter to finish and return to menu │
 └──────────────────────────────────────────┘""", default))
        clear()
        menu()


# Saves the report in each file format
def save_to_all_formats(fails, remaining_fails, success_fixes, audit_report):
    save_to_txt(fails, remaining_fails, success_fixes, audit_report, True)
    save_to_md(fails, remaining_fails, success_fixes, audit_report, True)
    save_to_csv(fails, remaining_fails, success_fixes, audit_report, True)
    # save_to_pdf(fails, remaining_fails, success_fixes, audit_report, True)
    input(colored("""
 ┌──────────────────────────────────────────┐
 │ Press Enter to finish and return to menu │
 └──────────────────────────────────────────┘""", default))
    clear()
    menu()


if __name__ == '__main__':
    try:
        # Checks Python version
        if sys.version_info[0] < 3:
            version = ".".join(map(str, sys.version_info[:3]))
            print("\nYou are using Python " + version)
            print(colored("\nPlease use Python 3 !\n", warning))
            print("Exiting...")
            wait(0.5)
            quit()
        # Checks if user is root
        elif is_root() == False:
            print(colored("\nPlease run this script as a privileged user.\nYou can do so with the command `sudo python3 audit.py`.\n", info))
            wait(1)
            quit()
        else:
            switch_to_en()
            main()
    # Manages keyboard interrupt from user
    except KeyboardInterrupt:
        print("\n\nInterrupted by user... Yes, you.")
