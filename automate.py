#!/usr/bin/python3
# -*- coding: utf-8 -*-
import os
import binascii
import logging
import argparse
import json
import subprocess
import re, time
import sys
import pexpect

logger = logging.getLogger(__name__)
#log_level = logging.ERROR
#log_level = logging.WARNING
log_level = logging.INFO
#log_level = logging.DEBUG

logging.basicConfig(format='%(asctime)s %(message)s', level=log_level)

hci_interface_down = 'sudo hciconfig hci0 down'
hci_interface_up = 'sudo hciconfig hci0 up'
hci_interface_piscan = 'sudo hciconfig hci0 piscan'
hci_interface_auth = 'sudo hciconfig hci0 auth'

ble_scan_command = 'sudo timeout 5 hcitool lescan'

ble_connect_command = 'sudo hcitool lecc '
ble_connect_success = 'Connection handle'
ble_connect_error = 'Could not create connection'

def strip_to_lines(output):
    lines = re.split('\r?\n', output.strip().decode("utf-8"))
    lines = list(set(lines))
    logger.info("LINES")
    logger.info(lines)
    return lines

def pexpect_session_feedback(child, command, pattern):
    before_output = b""
    after_output = b""
    try:
        child.sendline(command)
        child.expect(pattern)
        after_output += child.after
        
    #     output = b""
    #     while True:
    #         try:
    #             res = child.expect('.*commmand.*')
    #             output += child.after
    #         except pexpect.EOF:
    #             break

    except Exception as e:
        before_output += child.before
        #print(str(e))
        
    print("before:" + str(before_output))
    strip_to_lines(before_output)
    print("after:" + str(after_output))
    strip_to_lines(after_output)
    return(child, before_output, after_output)

def pexpect_feedback(command, pattern):
    before_output = b""
    after_output = b""
    try:
        child = pexpect.spawn(command)
        child.expect(pattern)
        after_output += child.after
        
    #     output = b""
    #     while True:
    #         try:
    #             res = child.expect('.*commmand.*')
    #             output += child.after
    #         except pexpect.EOF:
    #             break

    except Exception as e:
        before_output += child.before
        #print(str(e))
        
    print("before:" + str(before_output))
    strip_to_lines(before_output)
    print("after:" + str(after_output))
    strip_to_lines(after_output)
    return(child, before_output, after_output)

def connect_ble(address):
    output = subprocess_with_results(ble_connect_command + address)
    logger.info("connect_ble response:{}".format(output))
    if output[0:len(ble_connect_error)] == ble_connect_error:
        logger.info("connect_ble error")
        connect_ble(address)
    elif output[0:len(ble_connect_success)] == ble_connect_success:
        logger.info("connect_ble success")

def scan_ble(hci="hci0"):
    sleep_time = 0.2
    conn = pexpect.spawn(hci_interface_down)
    time.sleep(sleep_time)
    conn = pexpect.spawn(hci_interface_up)
    time.sleep(sleep_time)
    conn = pexpect.spawn("sudo timeout 10 hcitool lescan")
    time.sleep(sleep_time)

    conn.expect("LE Scan \.+")
    output = b""
    adr_pat = "(?P<addr>([0-9A-F]{2}:){5}[0-9A-F]{2}) (?P<name>.*)"
    while True:
        try:
            res = conn.expect(adr_pat)
            output += conn.after
        except pexpect.EOF:
            break

    lines = re.split('\r?\n', output.strip().decode("utf-8"))
    lines = list(set(lines))
    lines = [line for line in lines if re.match(adr_pat, line)]
    lines = [re.match(adr_pat, line).groupdict() for line in lines]
    lines = [line for line in lines if re.match('.*', line['name'])]
    logger.info(lines)
    return lines

def subprocess_with_results(command):
    process = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, universal_newlines=True)
    output = process.stdout
    return output

def shell_command_without_result(command, wait_time, terminate_flag):
    process = subprocess.Popen(command, universal_newlines=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(wait_time)
    if terminate_flag:
        process.terminate()

def shell_command_with_result(command, wait_time, terminate_flag):
    process = subprocess.Popen(command, universal_newlines=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    retcode = process.wait()
    time.sleep(wait_time)
    if terminate_flag:
        process.terminate()
    text = process.stdout.read()
    print(text)
    if len(text) > 0:
        return text
    
def manage_hci(reset, setup):
    sleep_time = 0.2
    if reset == True:
        shell_command_without_result(hci_interface_down, sleep_time, True)
        time.sleep(sleep_time)
        shell_command_without_result(hci_interface_up, sleep_time, True)
    if setup == True:
        shell_command_without_result(hci_interface_piscan, sleep_time, True)
        time.sleep(sleep_time)
        shell_command_without_result(hci_interface_auth, sleep_time, True)
    
def process_mac_addresses(mac_add_list):
    manage_hci(True, True)
    scan_ble()
    connect_ble('AC:23:3F:66:47:7D')
    #open_bluetoothctl()
    
#     child_before_after = pexpect_feedback("sudo ftp ftp.openbsd.org", '.*command.*')
#     print("before:" + str(child_before_after[0]))
    
    
    child_before_after = pexpect_feedback("bluetoothctl", 'Agent registered.*')

    child_before_after = pexpect_session_feedback(child_before_after[0], "info", ".*Connected: yes.*")
    
    child_before_after = pexpect_session_feedback(child_before_after[0], "pair", ".*Enter passkey.*")
    
    #"Failed to pair:"
    
    child_before_after = pexpect_session_feedback(child_before_after[0], "591522", ".*Pairing successful.*")
    
    child_before_after = pexpect_session_feedback(child_before_after[0], "menu gatt", ".*Print environment variables.*")
    
    child_before_after = pexpect_session_feedback(child_before_after[0], "list-attributes", ".*Print environment variables.*")
    
    child_before_after = pexpect_session_feedback(child_before_after[0], "select-attribute c5cc5001-127f-45ac-b0fc-7e46c3591334", ".*Print environment variables.*")
    
    child_before_after = pexpect_session_feedback(child_before_after[0], "write 0x0070", ".*Print environment variables.*")
    child_before_after = pexpect_session_feedback(child_before_after[0], "write 0x0011", ".*Print environment variables.*")
    child_before_after = pexpect_session_feedback(child_before_after[0], "write 0x0002", ".*Print environment variables.*")
    child_before_after = pexpect_session_feedback(child_before_after[0], "write 0x0004", ".*Print environment variables.*")
    
    #for mac in mac_add_list:
    #    logger.info("\t" + str(mac))
    #manage_hci(True, True)
    #ble_scan_result = shell_command_with_result(ble_scan_command, 10, False)
    #logger.info(ble_scan_result)

def main():
    parser = argparse.ArgumentParser(description='Help display')
    
    requiredNamed = parser.add_argument_group('required named arguments')
    requiredNamed.add_argument("-l", "--list", help="List of MAC Address to change BLE Tag mode parameters(view example files).", required=True)
    
    optionnalNamed = parser.add_argument_group('optional named arguments')
    optionnalNamed.add_argument("-o", "--output", help="Output log file.", required=False)

    args = parser.parse_args()
    
    # Log into a file
    if args.output is not None :
        # Check if files already exists
        if os.path.isfile(args.output):
            print('Error: log file already exists')
            exit(-1)
        el = (args.output).split('.')
        el.insert(-1, 'success')
        if os.path.isfile( ".".join(el) ):
            print('Error: success file output already exists')
            exit(-1)
        el = (args.output).split('.')
        el.insert(-1, 'error')
        if os.path.isfile( ".".join(el) ):
            print('Error: error file output already exists')
            exit(-1)
        root = logging.getLogger('')
        fh = logging.FileHandler(args.output)
        fh.setLevel(log_level)
        fh.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
        root.addHandler(fh)
    
    logger.info("Starting BLE Tag mode parameter updates")
    logger.info("")
    
    mac_add_list = []
     
    if args.list.find(".json") > 0:
        logger.info("Parse file in JSON mode")
        with open(args.list,'r') as json_file:
            data = json.load(json_file)
            for t in data:
                mac_add_list.append( t['Barcode'] )
    elif args.list.find(".txt") > 0:
        logger.info("Parse file in TXT mode")
        with open(args.list,'r') as txt_file:
            lines = txt_file.readlines()
            for l in lines:
                mac_add_list.append( l.rstrip() )
    else:
        logger.info("Error: {} is not in supported list format file. Only JSON and TXT are supported.".format(str(args.list)))
        exit(-1)
    
    logger.info("Found {} MAC addresses in {}".format(str(len(mac_add_list)),str(args.list)))

    process_mac_addresses(mac_add_list)

    logger.info("BLE Tag pair report: total={}".format(str(len(mac_add_list))))
    logger.info("Full process is finished.")
    exit(0)

#tcpdump_capture_unlimited_byte_packets = 'tcpdump -i {e} -s0 -w {c}'.format(e=eth_interface, c=cap_pcap_file)
#shell_result = shell_command_with_result(tcpdump_display_all_packets, 0, False)
#shell_command_without_result(tcpdump_capture_unlimited_byte_packets, capture_time, True)

if __name__ == '__main__':
    main()
