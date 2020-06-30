#!/usr/bin/python3
# -*- coding: utf-8 -*-
import re, time

def intelligent_match(source, match):
    start_index = source.index(match)
    print("start_index:" + str(start_index))
    end_index = len(match)
    print("end_index:" + str(end_index))
    source = source[start_index:start_index + end_index]
    return bool(match == source)

def main():
    print('sanity string testing')
    line = '\r\nFailed to pair: org.bluez.Error.ConnectionAttemptFailed'
    error = 'Failed to pair: org.bluez.Error.ConnectionAttemptFailed'
    print(intelligent_match(line, error))
        
if __name__ == '__main__':
    main()