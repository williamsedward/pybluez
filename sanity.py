#!/usr/bin/python3
# -*- coding: utf-8 -*-
import re, time

def intelligent_match(source, match):
    match_found = False
    try:
        start_index = source.index(match)
        print("start_index:" + str(start_index))
        end_index = len(match)
        print("end_index:" + str(end_index))
        source = source[start_index:start_index + end_index]
        match_found = bool(match == source)
    except Exception as e:
        #print(str(e))
        match_found = False
    return match_found

def main():
    print('sanity string testing')
    line = '\r\nFailed to pair: org.bluez.Error.ConnectionAttemptFailed'
    error = 'Failed to pair: org.bluez.Error.ConnectionAttemptFailed'
    print(intelligent_match(line, error))
        
if __name__ == '__main__':
    main()