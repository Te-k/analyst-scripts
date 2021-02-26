#!/usr/bin/env python

"""Extract Android backup files

Read and extract a tar file from an Android backup file. If the file is
encrypted, a password will be required to decrypt the file.
https://github.com/FloatingOctothorpe/dump_android_backup

Feb 2021 : updated to use cryptography instead of pyaes
"""

import argparse
import getpass
import hashlib
import io
import logging
import sys
import zlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

__version__ = '0.1.0'
__author__ = 'Floating Octothorpe'


PBKDF2_KEY_SIZE = 32

class AndroidBackupParseError(Exception):
    """Exception raised file parsing an android backup file"""
    pass

def to_utf8_bytes(input_bytes):
    """Emulate bytes being converted into a "UTF8 byte array"

    For more info see the Bouncy Castle Crypto package Strings.toUTF8ByteArray
    method:
      https://github.com/bcgit/bc-java/blob/master/core/src/main/java/org/bouncycastle/util/Strings.java#L142
    """
    output = []
    for byte in input_bytes:
        if byte < ord(b'\x80'):
            output.append(byte)
        else:
            output.append(ord('\xef') | (byte >> 12))
            output.append(ord('\xbc') | ((byte >> 6) & ord('\x3f')))
            output.append(ord('\x80') | (byte & ord('\x3f')))
    return bytes(output)

def decrypt_master_key_blob(key, aes_iv, cipher_text):
    """Decrypt the master key blob with AES"""

    cipher = Cipher(algorithms.AES(key), modes.CBC(aes_iv))
    aes = cipher.decryptor()

    plain_text = b''
    while len(plain_text) < len(cipher_text):
        offset = len(plain_text)
        plain_text += aes.update(cipher_text[offset:(offset + 16)])
    plain_text += aes.finalize()

    blob = io.BytesIO(plain_text)
    master_iv_length = ord(blob.read(1))
    master_iv = blob.read(master_iv_length)
    master_key_length = ord(blob.read(1))
    master_key = blob.read(master_key_length)
    master_key_checksum_length = ord(blob.read(1))
    master_key_checksum = blob.read(master_key_checksum_length)

    return master_iv, master_key, master_key_checksum

def check_header(backup_file, password=None):
    """Extract and validate the backup header"""
    header = {}

    with open(backup_file, 'rb') as backup:
        if backup.readline() != b'ANDROID BACKUP\n':
            raise AndroidBackupParseError('Unrecognised file format!')

        header['format_version'] = int(backup.readline())
        header['compression_version'] = int(backup.readline())
        header['encryption'] = backup.readline().decode('utf-8').strip()
        header['payload_offset'] = backup.tell()

        if header['format_version'] > 5:
            raise AndroidBackupParseError('Unsupported format version, \
                                          only version 1-5 is supported')
        if header['compression_version'] != 1:
            raise AndroidBackupParseError('Unsupported compression version, \
                                          only version 1 is supported')
        if not header['encryption'] in ['none', 'AES-256']:
            raise AndroidBackupParseError('Unsupported encryption scheme: %s' %
                                          header['encryption'])

        logging.debug('Format version: %d', header['format_version'])
        logging.debug('Compression version: %d', header['compression_version'])
        logging.debug('Encryption algorithm: %s', header['encryption'])

        if header['encryption'] == 'AES-256':

            if not password:
                password = getpass.getpass()

            header['user_salt'] = bytes.fromhex(backup.readline().decode('utf-8').strip())
            header['checksum_salt'] = bytes.fromhex(backup.readline().decode('utf-8').strip())
            header['pbkdf2_rounds'] = int(backup.readline())
            header['user_iv'] = bytes.fromhex(backup.readline().decode('utf-8').strip())
            header['master_key_blob'] = bytes.fromhex(backup.readline().decode('utf-8').strip())
            header['payload_offset'] = backup.tell()

            logging.debug('User password salt: %s', header['user_salt'].hex().upper())
            logging.debug('Master key checksum salt: %s', header['checksum_salt'].hex().upper())
            logging.debug('PBKDF2 rounds: %d', header['pbkdf2_rounds'])
            logging.debug('IV of the user key: %s', header['user_iv'].hex().upper())
            logging.debug('Master key blob: %s', header['master_key_blob'].hex().upper())

            key = hashlib.pbkdf2_hmac('sha1', password.encode('utf-8'),
                                      header['user_salt'],
                                      header['pbkdf2_rounds'], PBKDF2_KEY_SIZE)
            logging.debug('User key bytes: %s', key.hex().upper())

            try:
                header['master_iv'], header['master_key'], header['master_key_checksum'] = \
                        decrypt_master_key_blob(key, header['user_iv'], header['master_key_blob'])
            except TypeError:
                raise AndroidBackupParseError('Invalid decryption password')

            # v2 plus needs utf-8 byte array
            if header['format_version'] > 1:
                hmac_mk = to_utf8_bytes(header['master_key'])
            else:
                hmac_mk = header['master_key']

            calculated_checksum = hashlib.pbkdf2_hmac('sha1', hmac_mk,
                                                      header['checksum_salt'],
                                                      header['pbkdf2_rounds'],
                                                      PBKDF2_KEY_SIZE)

            if not header['master_key_checksum'] == calculated_checksum:
                raise AndroidBackupParseError('Invalid decryption password')

            logging.debug('Master key IV: %s', header['master_iv'].hex().upper())
            logging.debug('Master key: %s', header['master_key'].hex().upper())
            logging.debug('Master key checksum: %s', header['master_key_checksum'].hex().upper())

    return header

def extract_backup(backup_file, output, password, no_decompress):
    """Extract a tar file from an Android backup file."""

    try:
        header = check_header(backup_file, password)
    except (FileNotFoundError, AndroidBackupParseError) as error:
        logging.error(error)
        raise error

    with open(backup_file, 'rb') as backup:
        logging.debug('moving to payload offset (%d bytes)', header['payload_offset'])
        backup.seek(header['payload_offset'])

        with open(output, 'wb') as output_file:

            if header['encryption'] == 'AES-256':
                cipher = Cipher(algorithms.AES(header['master_key']), modes.CBC(header['master_iv']))
                decrypter = cipher.decryptor()
                data = b''
                chunk = backup.read(10000000)
                while chunk:
                    logging.debug("CHUNK")
                    data += decrypter.update(chunk)
                    chunk = backup.read(10000000)
                data = data + decrypter.finalize()
            else:
                data = backup.read()
            if no_decompress:
                logging.debug("Writing data without decompressing")
                output_file.write(data)
            else:
                logging.debug("start decompressing")
                output_file.write(zlib.decompress(data))

    logging.info('Successfully written data to "%s"', output)

def main():
    """Parse arguments and try to extract an Android backup"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('backup_file', metavar='BACKUP_FILE',
                        help='Android backup file to extract')
    parser.add_argument('output_file', metavar='OUTPUT_FILE',
                        help='File to write the extracted tar file to')
    parser.add_argument('-p', '--password', dest='password', metavar='PASSWORD',
                        help='Password to decrypt Android backup')
    parser.add_argument('-d', '--debug', dest='debug', action='store_true',
                        help='Enable debug messages')
    parser.add_argument('-n', '--no-decompress', action='store_true',
                        help='Do not decompress the archive')
    options = parser.parse_args()

    logging.basicConfig(stream=sys.stderr, level=logging.INFO,
                        format='[%(levelname)s]: %(message)s')
    if options.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    logging.debug('called with arguments: %s', vars(options))
    if options.backup_file == options.output_file:
        logging.error('The input and output file cannot be the same!')
        sys.exit(1)
    try:
        extract_backup(options.backup_file, options.output_file, options.password, options.no_decompress)
    except (FileNotFoundError, AndroidBackupParseError):
        sys.exit(1)

if __name__ == '__main__':
    main()
