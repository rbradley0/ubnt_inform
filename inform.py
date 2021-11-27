# coding: utf-8
'''
Unifi Inform Protocol plugin for Puffin WebServer, all code is from documentation about how the Unifi Inform Protocol works and functions.

This script is an updated working rewrite of the script published by Eric W <Brontide@GitHub> that uses Snappy, Zlib, pycryptodome, and Flask.
Snappy and pycryptodome are the only real deviations from the original because pysnappy fails to compile on my system and pycryto doesn't seem to
support AES-GCM mode.

Authors: Ryan Bradley <rbradley0@foxsys.org>

Credit: Eric W <Brontide@GitHub>, Felix Kaiser <fxkr@GitHub>, Jeffery Kog <jefferykog@GitHub>

'''

from binascii import a2b_hex, b2a_hex
from Crypto.Cipher import AES
from snappy import snappy
from struct import pack, unpack
import json
import zlib

MAGIC_BYTES = b'TNBU'
HEADER_FMT = "!4s I 6s H 16s I I"
'''
Inform packet header, Big Endian network format:
    Magic Bytes: TNBU
    Packet Version: 0
    Hardware Address/MAC Address
    Flags:
        bit 1 - Encrypted
        bit 2 - zlib compression
        bit 3 - snappy compression, possibly deprecated
        bit 4 -  AES-GCM mode w/ 40 byte header being AAD, last 16 bytes are validation tag
    IV - Encryption Initialization Value or Nonce
    Payload Version
    Payload Length
'''


DEFAULT_KEY = 'ba86f2bbe107c7c57eb5f2690775c712'
'''
Pre-adoption Key before device is managed, md5sum of "ubnt"
'''


def b2a_mac(MAC_ADDR):
    '''
    Convert 6 byte Hardware Address into hex represented string
    '''
    if MAC_ADDR is None:
        raise ValueError("Invalid MAC address")
    MAC = unpack('!BBBBBB', MAC_ADDR)
    return ':'.join(["{:02x}".format(x) for x in MAC])


def a2b_mac(MAC_ADDR):
    '''
    Coverts hex represented string in 6 byte Hardware Address
    '''
    if MAC_ADDR == None:
        return None
    MAC = [int(x, 16) for x in MAC_ADDR.split(':')]
    return pack('!BBBBBB', *MAC)


class Packet:
    def __init__(self, **kwargs):
        self.key = kwargs.get('key', None)
        self.try_adopt = kwargs.get('try_adopt', self.key == None)
        if "from_packet" in kwargs:
            self.raw_packet = kwargs['from_packet']
            self.decode()
            return  # What?
        self.MAC_ADDR = kwargs.get('MAC_ADDR', None)
        self.flags = kwargs.get('flags', 0)
        self.payload = kwargs.get('payload', None)

    def __repr__(self):
        return "Not Yet Implemented"

    def decode(self):
        raw_packet_length = len(self.raw_packet)
        if raw_packet_length < 40:
            raise ValueError(
                "Packet Length is less than 40 bytes, cannot decode")
        (magic, version, hw_addr, flags, iv, payload_version,
         payload_length) = unpack(HEADER_FMT, self.raw_packet[:40])
        if magic != MAGIC_BYTES:
            raise ValueError(
                f"Magic Bytes expect {MAGIC_BYTES}, got {magic} instead.")
        if raw_packet_length != 40+payload_length:
            raise ValueError(
                f"Packet Length {raw_packet_length} doesn't equal {40+payload_length}")
        if version != 0:
            raise ValueError(f"Unknown version {version}")
        if payload_version != 1:
            raise ValueError(f"Unknown payload version {version}")

        self.packet_version = version
        self.mac_address = b2a_mac(hw_addr)
        self.flags = flags
        self.nonce = iv
        self.payload_version = payload_version
        self.payload_length = payload_length
        self.encoded_payload = self.raw_packet[40:]
        payload = self.encoded_payload

        try:
            key = self.key
            if not key and self.try_adopt:
                key = DEFAULT_KEY
            key = a2b_hex(key)
            if self.isEncrypted:
                if self.isGcm:
                    cipher = AES.new(key, AES.MODE_GCM, nonce=self.nonce)
                    cipher.update(self.raw_packet[:40])
                    payload = cipher.decrypt_and_verify(
                        self.encoded_payload[:-16], self.encoded_payload[-16:])
                else:
                    cipher = AES.new(key, AES.MODE_CBC, iv=nonce)
                    payload = cipher.decrypt(self.encoded_payload)

            if self.isZlib:
                payload = zlib.decompress(payload)

            if self.isSnappy:
                payload = snappy.uncompress(payload)

            self.payload = payload.decode('utf-8')

        except Exception as e:
            print(e)

    @property
    def isEncrypted(self):
        '''
        Is Input AES-CBC mode?
        '''
        return (self.flags & 1) != 0

    @property
    def isZlib(self):
        '''
        Is Input Zlib compressed?
        '''
        return (self.flags & 2) != 0

    @property
    def isSnappy(self):
        '''
        Is Input Snappy compressed? (possibly deprecated)
        '''
        return (self.flags & 4) != 0

    @property
    def isGcm(self):
        '''
        Is Input AES-GCM mode?
        '''
        return (self.flags & 8) != 0
