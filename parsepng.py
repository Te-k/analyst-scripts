#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import argparse
import struct
import logging

""" parsepng.py: Parse a PNG file looking for weird things """

CHUNK_TYPES = {
    'IHDR': "Contains (in this order) the image's width, height, bit depth, color type, compression method, filter method, and interlace method",
    'PLTE': "contains the palette; list of colors",
    'IDAT': "contains the image, which may be split among multiple IDAT chunks",
    'IEND': "marks the image end",
    'bKGD': "gives the default background color",
    'cHRM': "gives the chromaticity coordinates of the display primaries and white point",
    'gAMA': "specifies gamma",
    'hIST': "can store the histogram, or total amount of each color in the image",
    'iCCP': "ICC color profile",
    'iTXt': "contains UTF-8 text, compressed or not, with an optional language tag",
    'pHYs': "holds the intended pixel size and/or aspect ratio of the image",
    'sBIT': "(significant bits) indicates the color-accuracy of the source data",
    'sPLT': "suggests a palette to use if the full range of colors is unavailable",
    'sRGB': "indicates that the standard sRGB color space is used",
    'sTER': "stereo-image indicator chunk for stereoscopic images",
    'tEXt': "can store text that can be represented in ISO/IEC 8859-1",
    'tIME': "stores the time that the image was last changed",
    'tRNS': "contains transparency information",
    'zTXt': "contains compressed text with the same limits as tEXt"
}

IMAGE_TYPE = {
    0: "Greyscale",
    2: "True colour",
    3: "Indexed-colour",
    4: "Greyscale with alpha",
    6: "Truecolour with alpha"
}

IMAGE_TYPE_BIT_DEPTH = {
    0: [1, 2, 4, 8, 16],
    2: [8, 16],
    3: [1, 2, 4, 8],
    4: [8, 16],
    6: [8, 16]
}


def xorrr(data, key):
    """Xor the given data with the key"""
    return map(lambda x: chr(ord(x) ^ key), data)


def parse_png(data, logger):
    """Parse PNG data"""
    header = data[:8]
    if header != "\x89PNG\x0d\x0a\x1a\x0a":
        logger.critical("Bad PNG header... Quitting...")
        return ''
    else:
        logger.debug("Correct PNG header")
    i = 8
    chunks = []
    end = False
    ichunk = 1
    while not end:
        length = struct.unpack('>I', data[i:i+4])[0]
        ctype = data[i+4:i+8]
        if ctype == 'IEND':
            end = True
        cdata = data[i+8:i+8+length]
        crc = data[i+8+length:i+12+length]
        logger.warn('%i - Chunk: %s - %i bytes' % (ichunk, ctype, length))
        comment = None

        if ctype not in CHUNK_TYPES.keys():
            logger.warn('\t- Bad chunk type %s' % ctype)
            comment = "bad chunk type"
            if length > 5000:
                # Look for PE header
                for key in range(0, 255):
                    res = xorrr(cdata[:1000], key)
                    if "This program cannot be run in DOS mode" in res:
                        logger.warn("\t- PE header found with XOR key 0x%x" % key)

        # Header analysis
        if ctype == 'IHDR':
            width = struct.unpack('>I', cdata[0:4])[0]
            height = struct.unpack('>I', cdata[4:8])[0]
            bit_depth = ord(cdata[8:9])
            colour_type = ord(cdata[9:10])
            compression = ord(cdata[10:11])
            filter_method = ord(cdata[11:12])
            interlace_method = ord(cdata[12:13])

            logger.warn("\t- Sixe %i x %i pixels" % (width, height))
            if colour_type not in IMAGE_TYPE.keys():
                logger.warn("\t- Unknown colour-type %i" % colour_type)
            else:
                logger.warn("\t- Colour-type : %i (%s)" % (colour_type, IMAGE_TYPE[colour_type]))
                if bit_depth not in IMAGE_TYPE_BIT_DEPTH[colour_type]:
                    logger.warn("\t- Invalid bit-depth for this colour-type %i" % bit_depth)

            if compression != 0:
                logger.warn("\t- Invalid compression method : %i" % compression)
            if filter_method != 0:
                logger.warn("\t- Invalid filter method : %i" % filter_method)
            if interlace_method not in [0, 1]:
                logger.warn("\t- Invalid interlace method : %i" % interlace_method)

            comment = "Sixe %i x %i pixels" % (width, height)
        if ctype == "tEXt":
            text = cdata.split("\x00")
            comment = "%s : %s" % (text[0], text[1])
            logger.warn("\t- " + comment)

        if ctype == "tIME":
            comment = "Last image modification : %i:%i:%i %02i/%02i/%i" % (
                    ord(cdata[4:5]),
                    ord(cdata[5:6]),
                    ord(cdata[6:7]),
                    ord(cdata[3:4]),
                    ord(cdata[2:3]),
                    struct.unpack('>H', cdata[:2])[0]
            )
            logger.warn("\t- " + comment)

        chunks.append({
            'length': length,
            'data': cdata,
            'type': ctype,
            'crc': crc,
            'comment': comment
        })
        i += length + 12
        ichunk += 1

    if i > len(data):
        extra = data[i:]
        logger.warn("Extra data : %i bytes" % extra)
    else:
        extra = None

    return({'header': header, 'chunks': chunks, 'extra': extra})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Analyze a PNG file')
    parser.add_argument('FILE', help='a weird PNG file')
    parser.add_argument('--chunk', '-c', type=int, help='Dump the content of the given chunk')
    parser.add_argument('--verbose', '-v', action='store_true', help='Be verbose')
    args = parser.parse_args()

    f = open(args.FILE, 'rb')
    data = f.read()
    f.close()

    if args.chunk is None:
        if args.verbose:
            logging.basicConfig(format='%(message)s', level=logging.DEBUG)
        else:
            logging.basicConfig(format='%(message)s', level=logging.WARNING)
        parse_png(data, logging)
    else:
        logging.basicConfig(format='%(message)s', level=logging.CRITICAL)
        infos = parse_png(data, logging)
        print(infos['chunks'][args.chunk - 1]['data'])
