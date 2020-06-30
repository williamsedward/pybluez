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


def strip_to_lines(name, output):
    lines = re.split('\r?\n', output.decode('utf-8'))
    logger.info(name)
    for l in lines:
        logger.info(l)
    return lines

def intelligent_match(match, source):
#     start_index = source.index(match)
#     print("start_index:" + str(start_index))
#     end_index = len(match) + start_index
#     print("end_index:" + str(end_index))
#     source = source[start_index:end_index]
    return bool(match == source)

def debug_output(name, output):
    if len(output) > 0:
        logger.info(name + ' b:\r\n' + str(output))
        return strip_to_lines(name + ':\r\n', output)
    
def return_valid_output(before_output, after_output):
    before_output_lines = debug_output('before_output', before_output)
    after_output_lines = debug_output('after_output', after_output)
    if before_output_lines is not None:
        return (before_output_lines, False)
    elif after_output_lines is not None:
        return (after_output_lines, True)

def pexpect_session_feedback(conn, command, pattern):
    before_output = b''
    after_output = b''
    try:
        conn.sendline(command)
        conn.expect(pattern)
        after_output += conn.after
    except Exception as e:
        before_output += conn.before
        #print(str(e))
    output = return_valid_output(before_output, after_output)
    return(conn, output)

def pexpect_feedback(command, pattern):
    before_output = b''
    after_output = b''
    try:
        conn = pexpect.spawn(command)
        conn.expect(pattern)
        after_output += conn.after
    except Exception as e:
        before_output += conn.before
        #print(str(e))
    output = return_valid_output(before_output, after_output)
    return(conn, output)

def open_bluetoothctl():
    sleep_time = 0.3
    pair_code = 409132
    error_flag = False
    logger.info('open_bluetoothctl()')
    conn_output = pexpect_feedback('bluetoothctl', 'Agent registered.*')
    time.sleep(sleep_time)
    
    for line in conn_output[1][0]:
        if len(line) > 0:
            if intelligent_match('[bluetooth]', line):
                logger.info('ERROR [bluetooth]')
                error_flag = True
            if intelligent_match('Failed to pair: org.bluez.Error.ConnectionAttemptFailed', line):
                logger.info('ERROR Failed to pair')
                error_flag = True
    
    if not error_flag:
        conn_output = pexpect_session_feedback(conn_output[0], 'info', '.*Connected: yes.*')
        time.sleep(sleep_time)
        
        for line in conn_output[1][0]:
            if len(line) > 0:
                if intelligent_match('Missing device address argument', line):
                    logger.info('ERROR Not Connected')
                    error_flag = True

    if not error_flag:
        conn_output = pexpect_session_feedback(conn_output[0], 'pair', '.*Enter passkey.*')
        time.sleep(sleep_time)
        
        for line in conn_output[1][0]:
            if len(line) > 0:
                if intelligent_match('Missing device address argument', line):
                    logger.info('ERROR Not Connected')
                    error_flag = True
    
    if not error_flag:
        conn_output = pexpect_session_feedback(conn_output[0], str(pair_code), '.*Pairing successful.*')
        time.sleep(sleep_time)
        conn_output = pexpect_session_feedback(conn_output[0], 'menu gatt', '.*Print environment variables.*')
        time.sleep(sleep_time)
        conn_output = pexpect_session_feedback(conn_output[0], 'list-attributes', '.*Print environment variables.*')
        time.sleep(sleep_time)
        conn_output = pexpect_session_feedback(conn_output[0], 'select-attribute c5cc5001-127f-45ac-b0fc-7e46c3591334', '.*Print environment variables.*')
        time.sleep(sleep_time)
        conn_output = pexpect_session_feedback(conn_output[0], 'write 0x70', '.*Print environment variables.*')
        conn_output = pexpect_session_feedback(conn_output[0], 'write 0x11', '.*Print environment variables.*')
        conn_output = pexpect_session_feedback(conn_output[0], 'write 0x02', '.*Print environment variables.*')
        conn_output = pexpect_session_feedback(conn_output[0], 'write 0x04', '.*Print environment variables.*')

def connect_ble(address):
    sleep_time = 0.3
    conn_output = pexpect_feedback(ble_connect_command + address, 'Connection handle.*')
    time.sleep(sleep_time)
    
    for line in conn_output[1][0]:
        if len(line) > 0:
            if intelligent_match('Could not create connection: Connection timed out', line):
                logger.info('ERROR Connection timed out')
                time.sleep(sleep_time)
            if intelligent_match('Could not create connection: Input/output error', line):
                logger.info('ERROR Input/output error')
                manage_hci(True, False)
        
    return conn_output[1][1]

def scan_ble(hci='hci0'):
    sleep_time = 0.2
    logger.info('scan_ble()')
    conn = pexpect.spawn('sudo timeout 10 hcitool lescan')
    time.sleep(sleep_time)

    conn.expect('LE Scan \.+')
    output = b''
    adr_pat = '(?P<addr>([0-9A-F]{2}:){5}[0-9A-F]{2}) (?P<name>.*)'
    while True:
        try:
            res = conn.expect(adr_pat)
            output += conn.after
        except pexpect.EOF:
            break

    lines = re.split('\r?\n', output.strip().decode('utf-8'))
    lines = list(set(lines))
    lines = [line for line in lines if re.match(adr_pat, line)]
    lines = [re.match(adr_pat, line).groupdict() for line in lines]
    lines = [line for line in lines if re.match('.*', line['name'])]
    for l in lines:
        logger.info(l)
    return lines

def manage_hci(reset, setup):
    sleep_time = 0.2
    logger.info('manage_hci()')
    if reset == True:
        conn = pexpect.spawn(hci_interface_down)
        time.sleep(sleep_time)
        conn = pexpect.spawn(hci_interface_up)
        time.sleep(sleep_time)
    if setup == True:
        conn = pexpect.spawn(hci_interface_piscan)
        time.sleep(sleep_time)
        conn = pexpect.spawn(hci_interface_auth)
        time.sleep(sleep_time)

def process_mac_addresses(mac_add_list):
    connected = False
    tries = 0
    sleep_time = 0.2
    
    for mac in mac_add_list:
        mac_address = ':'.join(format(s, '02x') for s in bytes.fromhex(mac))
        logger.info('\t' + mac_address.upper())
    
    manage_hci(True, True)
    scan_ble()

    while not connected and tries < 3:
        tries += 1
        logger.info('connect_ble() tries:' + str(tries))
        connected = connect_ble('AC:23:3F:66:47:7E')
        time.sleep(sleep_time)
        if connected:
            logger.info('SUCCESS Connected')
            break

    if connected:
        open_bluetoothctl()

def main():
    parser = argparse.ArgumentParser(description='Help display')

    requiredNamed = parser.add_argument_group('required named arguments')
    requiredNamed.add_argument('-l', '--list', help='List of MAC Address to change BLE Tag mode parameters(view example files).', required=True)

    optionnalNamed = parser.add_argument_group('optional named arguments')
    optionnalNamed.add_argument('-o', '--output', help='Output log file.', required=False)

    args = parser.parse_args()

    # Log into a file
    if args.output is not None :
        # Check if files already exists
        if os.path.isfile(args.output):
            print('Error: log file already exists')
            exit(-1)
        el = (args.output).split('.')
        el.insert(-1, 'success')
        if os.path.isfile( '.'.join(el) ):
            print('Error: success file output already exists')
            exit(-1)
        el = (args.output).split('.')
        el.insert(-1, 'error')
        if os.path.isfile( '.'.join(el) ):
            print('Error: error file output already exists')
            exit(-1)
        root = logging.getLogger('')
        fh = logging.FileHandler(args.output)
        fh.setLevel(log_level)
        fh.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
        root.addHandler(fh)

    logger.info('Starting BLE Tag mode parameter updates')
    logger.info('')

    mac_add_list = []

    if args.list.find('.json') > 0:
        logger.info('Parse file in JSON mode')
        with open(args.list,'r') as json_file:
            data = json.load(json_file)
            for t in data:
                mac_add_list.append( t['Barcode'] )
    elif args.list.find('.txt') > 0:
        logger.info('Parse file in TXT mode')
        with open(args.list,'r') as txt_file:
            lines = txt_file.readlines()
            for l in lines:
                mac_add_list.append( l.rstrip() )
    else:
        logger.info('Error: {} is not in supported list format file. Only JSON and TXT are supported.'.format(str(args.list)))
        exit(-1)

    logger.info('Found {} MAC addresses in {}'.format(str(len(mac_add_list)),str(args.list)))

    process_mac_addresses(mac_add_list)

    logger.info('BLE Tag pair report: total={}'.format(str(len(mac_add_list))))
    logger.info('Full process is finished.')
    exit(0)

#tcpdump_capture_unlimited_byte_packets = 'tcpdump -i {e} -s0 -w {c}'.format(e=eth_interface, c=cap_pcap_file)
#shell_result = shell_command_with_result(tcpdump_display_all_packets, 0, False)
#shell_command_without_result(tcpdump_capture_unlimited_byte_packets, capture_time, True)

if __name__ == '__main__':
    main()