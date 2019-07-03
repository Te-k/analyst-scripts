#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
from struct import unpack
import logging

COMPONENTS = {1: 'Y', 2: 'Cb', 3: 'Cr', 4: 'I', 5: 'Q'}

def parse_app(data, logger):
    """
    Parse APP0 header
    """
    PIXEL_DENSITY_UNITS = {
        0: 'No units',
        1: 'Pixels per inch',
        2: 'Pixels per cm'
    }
    infos = {'errors': []}
    infos['length'] = len(data)
    if data[0:4] != b'JFIF':
        infos['errors'].append('Invalid JFIF Identifier')
    infos['identifier'] = data[0:5]
    infos['JFIF_version'] = '%i.%i' % unpack('>BB', data[5:7])
    if data[7] not in PIXEL_DENSITY_UNITS:
        infos['errors'].append('Invalid pixel density unit %i' % data[7])
        infos['density_unit'] = data[7]
    else:
        infos['density_unit'] = PIXEL_DENSITY_UNITS[data[7]]
    infos['density'] = '%ix%i' % unpack('>HH', data[8:12])
    infos['thumbnail'] = '%ix%i' % unpack('>BB', data[12:14])
    return infos


def parse_DQT(data, logger):
    """
    Parse Quantization Table
    """
    infos = {'errors': []}
    infos['length'] = len(data)
    infos['DQT_id'] = data[0] & 0x0f
    infos['DQT_precision'] = data[0] >> 4
    return infos


def parse_SOF0(data, logger):
    infos = {'errors': []}
    infos['length'] = len(data)
    infos['bits_per_sample'] = data[0]
    infos['height'] = unpack('>H', data[1:3])[0]
    infos['width'] = unpack('>H', data[3:5])[0]
    infos['nb_components'] = data[5]
    # Components not parsed
    return infos


def parse_DHT(data, logger):
    DHT_TYPE= {0: 'DC', 1: 'AC'}
    infos = {'errors': []}
    infos['length'] = len(data)
    infos['dht_id'] = data[0] & 0x0f
    infos['dht_type'] = DHT_TYPE[(data[0] >> 4) & 1]
    return infos


def parse_SOS(data, logger):
    infos = {'errors': []}
    infos['length'] = len(data)
    infos['nb_components'] = data[0]
    infos['components'] = []
    for i in range(infos['nb_components']):
        infos['components'].append('%s AC%i DC%i' %
                (
                    COMPONENTS[data[i*2+1]],
                    data[i*2+2] & 0x0f,
                    (data[i*2+2] >> 4) & 0x0f
                    )
        )
    return infos


def parse_APPn(data, logger):
    infos = {'errors': []}
    infos['length'] = len(data)
    infos['data'] = data
    return infos


def parse_exif(data, logger):
    # TODO
    infos = {'errors': []}
    infos['length'] = len(data)
    infos['data'] = data
    return infos


SEGMENT_TYPES = {
    b'\xff\xd8': {'name': 'Start Of Image'},
    b'\xff\xe0': {'name': 'APP0', 'parser': parse_app},
    b'\xff\xdb': {'name': 'Quantization Table', 'parser': parse_DQT},
    b'\xff\xc0': {'name': 'Start Of Frame (baseline)', 'parser': parse_SOF0},
    b'\xff\xc4': {'name': 'Huffman Table', 'parser': parse_DHT},
    b'\xff\xda': {'name': 'Start of Scan', 'parser': parse_SOS},
    b'\xff\xfe': {'name': 'Comment', 'parser': parse_APPn},
    b'\xff\xe1': {'name': 'Exif', 'parser': parse_exif}
}


def parse_jpg(data, logger):
    """
    Parse a JPEG file
    """
    segments = []
    if data[:2] != b'\xff\xd8':
        logger.critical("Bad JFIF header... Quitting...")
        return segments
    i = 2
    finished = False
    while not finished:
        logger.debug('%i - %s' % (i, data[i:i+2]))
        new_segment = {'address': i}
        if data[i:i+2] == b'\xff\xd9':
            new_segment['name'] = 'End of Image'
            new_segment['length'] = 0
            finished = True
        else:
            length = unpack('>H', data[i+2:i+4])[0]
            if data[i:i+2] in SEGMENT_TYPES:
                new_segment['name'] = SEGMENT_TYPES[data[i:i+2]]['name']
                if 'parser' in SEGMENT_TYPES[data[i:i+2]]:
                    new_segment.update(SEGMENT_TYPES[data[i:i+2]]['parser'](data[i+4:i+length+4], logger))
                if data[i:i+2] == b'\xff\xda':
                    i += length + 2
                    # Start of scan, consider the raw data here
                    data_length = 0
                    no_more_data = False
                    while not no_more_data:
                        if data[i+data_length] == 0xff:
                            if data[i+data_length+1] != 0:
                                no_more_data = True
                            else:
                                data_length += 1
                        else:
                            data_length += 1
                    new_segment['data_length'] = data_length
                    i += data_length
                else:
                    i += length + 2
            else:
                if data[i] == 0xff and data[i+1] > 0:
                    # APPn
                    new_segment['name'] = 'Application-Specific APP%i' % (data[i+1] - 0xe0)
                    new_segment.update(parse_APPn(data[i+4:i+length+4], logger))
                else:
                    new_segment['name'] = 'Unknown'
                    new_segment['prelude'] = data[i:i+2]
                    finished = True
                i += length + 2
        segments.append(new_segment)
    return segments


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Analyze a PNG file')
    parser.add_argument('FILE', help='a weird PNG file')
    parser.add_argument('--segments', '-s',
            action='store_true', help='Dump the content of the given chunk')
    parser.add_argument('--verbose', '-v', action='store_true', help='Be verbose')
    args = parser.parse_args()
    with open(args.FILE, 'rb') as f:
        data = f.read()

    if args.verbose:
        logging.basicConfig(format='%(message)s', level=logging.DEBUG)
    else:
        logging.basicConfig(format='%(message)s', level=logging.WARNING)
    infos = parse_jpg(data, logging)
    if args.segments:
        print('%10s | %-25s | %s' % ('Address', 'Segment', 'Size'))
        for segment in infos:
            print('%10i | %-25s | %i' % (segment['address'], segment['name'], segment['length']))
    else:
        for segment in infos:
            print('------------- %s' % segment['name'])
            for s in segment:
                if s is not 'name':
                    if isinstance(segment[s], list):
                        if len(segment[s]) > 0:
                            print('-%s' % s)
                            for d in segment[s]:
                                print('\t-%s' % d)
                    else:
                        print('-%s: %s' % (s, segment[s]))
