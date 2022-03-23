import os, time
import subprocess
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
        print('Error: '  + err)
        return err


def audit():
    print("\nBeginning audit...\n")
    audits = [
        audit_2_1_1_1,
        audit_2_1_3,
        audit_2_1_4,
        audit_2_1_5,
        audit_2_1_6,
        audit_2_1_7,
        audit_2_1_8
    ]
    for func in audits:
        time.sleep(0.5)
        func()
        print("")
    print(colored("Finished!", success))

def main():
    print("\nHello there!")
    time.sleep(1)
    menu()


##############################
# 2 - Services (Workstation) #
##############################

# systemctl --now mask <service_name>

# 2.1.1 Time Synchronization

# 2.1.1.1 Ensure time synchronization is in use
def audit_2_1_1_1():
    name = "2.1.1.1 Ensure time synchronization is in use"
    passed = False
    command1 = "systemctl is-enabled systemd-timesyncd"
    command2 = "dpkg -s chrony"
    command3 = "dpkg -s ntp"

    result1 = exec_cmd(command1)
    if result1 == "enabled":
        passed = True
        print(colored("[✓] " + name, success))
    else:
        print(colored("[X] " + name, warning))
    
    # result2 = execute_command(command2)
    # result3 = execute_command(command3)


# 2.1.3 Ensure Avahi Server is not installed
def audit_2_1_3():
    name = "2.1.3 Ensure Avahi Server is not installed"
    passed = False
    command = "dpkg -s avahi-daemon | grep -E '(Status:|not installed)'"
    result = exec_cmd(command)
    substring = "dpkg-query: package 'avahi-daemon' is not installed and no information is available"
    if substring in result:
        passed = True
        print(colored("[✓] " + name, success))
    else:
        print(colored("[X] " + name, warning))


# 2.1.4 Ensure CUPS is not installed
def audit_2_1_4():
    name = "2.1.4 Ensure CUPS is not installed"
    passed = False
    command = "dpkg -s cups | grep -E '(Status:|not installed)'"
    result = exec_cmd(command)
    substring = "dpkg-query: package 'cups' is not installed and no information is available"
    if substring in result:
        passed = True
        print(colored("[✓] " + name, success))
    else:
        print(colored("[X] " + name, warning))


# 2.1.5 Ensure DHCP Server is not installed
def audit_2_1_5():
    name = "2.1.5 Ensure DHCP Server is not installed"
    passed = False
    command = "dpkg -s isc-dhcp-server | grep -E '(Status:|not installed)'"
    result = exec_cmd(command)
    substring = "dpkg-query: package 'isc-dhcp-server' is not installed and no information is available"
    if substring in result:
        passed = True
        print(colored("[✓] " + name, success))
    else:
        print(colored("[X] " + name, warning))


# 2.1.6 Ensure LDAP server is not installed
def audit_2_1_6():
    name = "2.1.6 Ensure LDAP Server is not installed"
    passed = False
    command = "dpkg -s slapd | grep -E '(Status:|not installed)'"
    result = exec_cmd(command)
    substring = "dpkg-query: package 'slapd' is not installed and no information is available"
    if substring in result:
        passed = True
        print(colored("[✓] " + name, success))
    else:
        print(colored("[X] " + name, warning))


# 2.1.7 Ensure NFS is not installed
def audit_2_1_7():
    name = "2.1.7 Ensure NFS is not installed"
    passed = False
    command = "dpkg -s nfs-kernel-server | grep -E '(Status:|not installed)'"
    result = exec_cmd(command)
    substring = "dpkg-query: package 'nfs-kernel-server' is not installed and no information is available"
    if substring in result:
        passed = True
        print(colored("[✓] " + name, success))
    else:
        print(colored("[X] " + name, warning))


# 2.1.8 Ensure DNS Server is not installed
def audit_2_1_8():
    name = "2.1.8 Ensure DNS Server is not installed"
    passed = False
    command = "dpkg -s bind9 | grep -E '(Status:|not installed)'"
    result = exec_cmd(command)
    substring = "dpkg-query: package 'bind9' is not installed and no information is available"
    if substring in result:
        passed = True
        print(colored("[✓] " + name, success))
    else:
        print(colored("[X] " + name, warning))


main()
