"""Tries to crack AES encryption of a given config.bin"""
import argparse
import sys
import hashlib

from Cryptodome.Cipher import AES

import zcu


def bruteforce_generator(offset=0, increment=1):
    counter = offset
    while True:
        yield counter.to_bytes(16, 'little')
        counter += increment

def dictionary_generator():
    keys = [
        # known used keys
        b'Wj',
        b'MIK@0STzKpB%qJZe',
        b'MIK@0STzKpB%qJZf',
        b'402c38de39bed665',
        b'm8@96&ZG3Nm7N&Iz',
        b'GrWM2Hz&LTvz&f^5',
        b'GrWM3Hz&LTvz&f^9',
        b'Renjx%2$CjM',
        b'tHG@Ti&GVh@ql3XN',
        # default value
        b'Hello! world,',
        # MAC
        b'C4:A3:66:6F:16:62',
        b'c4:a3:66:6f:16:62',
        b'C4-A3-66-6F-16-62',
        b'c4-a3-66-6f-16-62',
        b'C4A3666F1662',
        b'c4a3666f1662',
        b'C4A366',
        # DevInfo/CfgLable
        b'H268NV1.0_OTE_Default_01',
        # Device Serial No.
        b'268EG8JG7K21834',
        b'268eg8jg7k21834',
        # software version
        b'V1.0.0_OTET12lw4o6P9A',
        b'Speedport Entry 2i',
        # guesswork
        b'Admin',
        b'root',
        b'zte',
        b'speedport-entry-2i.ote.gr',
        b'C4A366268EG8JG7K21834',
        ]

    for key in keys:
        for k in [
                key,
                key.lower(),
                key.upper(),
                # md5 of key
                hashlib.md5(key).hexdigest().encode('utf-8'),
                hashlib.md5(key).hexdigest().encode('utf-8')[16:],
                # md5 of lowercase key
                hashlib.md5(key.lower()).hexdigest().encode('utf-8'),
                hashlib.md5(key.lower()).hexdigest().encode('utf-8')[16:],
                # md5 of uppercase key
                hashlib.md5(key.upper()).hexdigest().encode('utf-8'),
                hashlib.md5(key.upper()).hexdigest().encode('utf-8')[16:],
            ]:
            yield k.ljust(16, b'\0')[:16]

def try_crack(data, generator):
    # iterate until successful
    for aes_key in generator:
        decrypted = AES.new(aes_key, AES.MODE_ECB).decrypt(data)
        # print(aes_key, decrypted[:16])
        if decrypted[:8] == b'\x01\x02\x03\x04\x00\x00\x00\x00':
            return aes_key
    return None

def main():
    """the main function"""
    parser = argparse.ArgumentParser(description='Tries to determine aes key of config.bin',
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('infile', type=argparse.FileType('rb'),
                        help='Configuration file (config.bin)')
    parser.add_argument('--bruteforce', action='store_true',
                        help='Use bruteforce generator (hint: bad idea!)')
    args = parser.parse_args()

    infile = args.infile
    zcu.zte.read_header(infile)
    zcu.zte.read_signature(infile)
    payload_type = zcu.zte.read_payload_type(infile)
    # only attempt to decrypt an aes config.bin
    assert payload_type == 2

    # skip header
    infile.read(12)
    # read 16 byte block
    data = infile.read(128)
    # select generator
    generator = bruteforce_generator() if args.bruteforce else dictionary_generator()
    # start cracking
    res = try_crack(data, generator)
    if res is not None:
        print('Found key %r' % res)
    else:
        print('Search exhausted. No key found.')

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("CTRL+C detected. Exiting.")
        sys.exit()
