#!/usr/bin/env python3
import subprocess

def run_command(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        return f"Error executing {' '.join(command)}: {e}"

def print_section(title):
    print("\n" + "=" * 50)
    print(f"{title}")
    print("=" * 50)

def check_weak_permissions(paths=['/etc', '/usr/local/bin', '/Users']):
    print_section("Checking for Weak Permissions")
    for path in paths:
        print(f"{path}: {run_command(['ls', '-ld', path])}")

def check_sip_status():
    print_section("Checking System Integrity Protection (SIP) Status")
    print(run_command(['csrutil', 'status']))

def check_secure_boot_gatekeeper():
    print_section("Checking Secure Boot & Gatekeeper Status")
    print(run_command(['spctl', '--status']))

def check_filevault_status():
    print_section("Checking FileVault Encryption Status")
    print(run_command(['fdesetup', 'status']))

def check_remote_login():
    print_section("Checking Remote Login (SSH) Status")
    print(run_command(['systemsetup', '-getremotelogin']))

def check_running_services():
    print_section("Checking Running Services and Daemons")
    print(run_command(['launchctl', 'list']))

def check_open_ports():
    print_section("Checking Open Network Ports")
    print(run_command(['netstat', '-an']))

def check_outdated_software():
    print_section("Checking for Outdated Software")
    print(run_command(['softwareupdate', '--list']))

def check_firewall_status():
    print_section("Checking Firewall Status")
    status = run_command(['defaults', 'read', '/Library/Preferences/com.apple.alf', 'globalstate'])
    print(f"Firewall status: {'Enabled' if status == '1' else 'Disabled'}")

def check_unsigned_apps():
    print_section("Checking for Running Unsigned Applications")
    result = run_command(['codesign', '-dr', '-', '--deep', '/Applications/*'])
    unsigned_apps = [line for line in result.split('\n') if 'not signed' in line]
    if unsigned_apps:
        print("Warning: Found unsigned applications:")
        for app in unsigned_apps:
            print(app)
    else:
        print("All applications appear to be signed.")

def main():
    print("\nMacOS Auditor - Security Audit Tool\n")
    check_weak_permissions()
    check_sip_status()
    check_secure_boot_gatekeeper()
    check_filevault_status()
    check_remote_login()
    check_running_services()
    check_open_ports()
    check_outdated_software()
    check_firewall_status()
    check_unsigned_apps()

if __name__ == "__main__":
    main()
