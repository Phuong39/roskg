# https://github.com/Ygnecz/MTLic

import sys
import struct

from sha256 import SHA256

MIKRO_BASE64_CHARACTER_TABLE = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
SOFTWARE_ID_CHARACTER_TABLE = b'TN0BYX18S5HZ4IA67DGF3LPCJQRUK9MW2VE'
MIKRO_SHA256_K = (
  0x0548D563, 0x98308EAB, 0x37AF7CCC, 0xDFBC4E3C,
  0xF125AAC9, 0xEC98ACB8, 0x8B540795, 0xD3E0EF0E,
  0x4904D6E5, 0x0DA84981, 0x9A1F8452, 0x00EB7EAA,
  0x96F8E3B3, 0xA6CDB655, 0xE7410F9E, 0x8EECB03D,
  0x9C6A7C25, 0xD77B072F, 0x6E8F650A, 0x124E3640,
  0x7E53785A, 0xE0150772, 0xC61EF4E0, 0xBC57E5E0,
  0xC0F9A285, 0xDB342856, 0x190834C7, 0xFBEB7D8E,
  0x251BED34, 0x0E9F2AAD, 0x256AB901, 0x0A5B7890,
  0x9F124F09, 0xD84A9151, 0x427AF67A, 0x8059C9AA,
  0x13EAB029, 0x3153CDF1, 0x262D405D, 0xA2105D87,
  0x9C745F15, 0xD1613847, 0x294CE135, 0x20FB0F3C,
  0x8424D8ED, 0x8F4201B6, 0x12CA1EA7, 0x2054B091,
  0x463D8288, 0xC83253C3, 0x33EA314A, 0x9696DC92,
  0xD041CE9A, 0xE5477160, 0xC7656BE8, 0x5179FE33,
  0x1F4726F1, 0x5F393AF0, 0x26E2D004, 0x6D020245,
  0x85FDF6D7, 0xB0237C56, 0xFF5FBD94, 0xA8B3F534
)

def encode_software_id(decodedSoftwareId):
  decodedSoftwareId = decodedSoftwareId.replace('-', '')

  encodedSoftwareId = 0
  for i in reversed(range(len(decodedSoftwareId))):
    encodedSoftwareId *= len(SOFTWARE_ID_CHARACTER_TABLE)
    encodedSoftwareId += SOFTWARE_ID_CHARACTER_TABLE.index(ord(decodedSoftwareId[i]))
  
  return encodedSoftwareId

def decode_software_id(encodedSoftwareId):
  decodedSoftwareId = ''
  for i in range(8):
    decodedSoftwareId += chr(SOFTWARE_ID_CHARACTER_TABLE[s % SOFTWARE_ID_CHARACTER_TABLE.length])
    s //= SOFTWARE_ID_CHARACTER_TABLE.length
    if i == 3:
      decodedSoftwareId += '-'
  
  return decodedSoftwareId

def to32bits(v):
  return (v + (1 << 32)) % (1 << 32)

def rotl(n, d):
    return (n << d) | (n >> (32 - d))

def encode_license_payload(s):
  s = list(struct.unpack('>' + 'I' * (len(s) // 4), s))
  for i in reversed(range(16)):
    s[(i+0) % 4] = to32bits(rotl(s[(i+3) % 4], MIKRO_SHA256_K[i*4+3] & 0x0F) ^ (s[(i+0) % 4] - s[(i+3) % 4]))
    s[(i+3) % 4] = to32bits(s[(i+3) % 4] + s[(i+1) % 4] + MIKRO_SHA256_K[i*4+3])

    s[(i+1) % 4] = to32bits(rotl(s[(i+2) % 4], MIKRO_SHA256_K[i*4+2] & 0x0F) ^ (s[(i+1) % 4] - s[(i+2) % 4]))
    s[(i+0) % 4] = to32bits(s[(i+0) % 4] + s[(i+2) % 4] + MIKRO_SHA256_K[i*4+2])

    s[(i+2) % 4] = to32bits(rotl(s[(i+1) % 4], MIKRO_SHA256_K[i*4+1] & 0x0F) ^ (s[(i+2) % 4] - s[(i+1) % 4]))
    s[(i+1) % 4] = to32bits(s[(i+1) % 4] + s[(i+3) % 4] + MIKRO_SHA256_K[i*4+1])

    s[(i+3) % 4] = to32bits(rotl(s[(i+0) % 4], MIKRO_SHA256_K[i*4+0] & 0x0F) ^ (s[(i+3) % 4] - s[(i+0) % 4]))
    s[(i+2) % 4] = to32bits(s[(i+2) % 4] + s[(i+0) % 4] + MIKRO_SHA256_K[i*4+0])

  encodedLicensePayload = b''
  for x in s:
    encodedLicensePayload += x.to_bytes(4, 'big')

  return encodedLicensePayload

def mikro_base64_encode(data, pad = False):
    encoded = ''

    left = 0
    for i in range(0, len(data)):
      if left == 0:
        encoded += chr(MIKRO_BASE64_CHARACTER_TABLE[data[i] & 0x3F])
        left = 2
      else:
        if left == 6:
          encoded += chr(MIKRO_BASE64_CHARACTER_TABLE[data[i - 1] >> 2])
          encoded += chr(MIKRO_BASE64_CHARACTER_TABLE[data[i] & 0x3F])
          left = 2
        else:
          index1 = data[i - 1] >> (8 - left)
          index2 = data[i] << (left)
          encoded += chr(MIKRO_BASE64_CHARACTER_TABLE[(index1 | index2) & 0x3F])
          left += 2

    if left != 0:
      encoded += chr(MIKRO_BASE64_CHARACTER_TABLE[data[len(data) - 1] >> (8 - left)])

    if pad:
      for i in range(0, (4 - len(encoded) % 4) % 4):
        encoded += '='

    return encoded

class MikroSHA256(SHA256):
  K = MIKRO_SHA256_K
  INITIAL_STATE = SHA256.State(
    0x5B653932, 0x7B145F8F, 0x71FFB291, 0x38EF925F,
    0x03E1AAF9, 0x4A2057CC, 0x4CAF4DD9, 0x643CC9EA
  )

def mikro_sha256(data):
  return bytearray(MikroSHA256(data).digest())

def printBytes(v):
  for i in range(len(v) // 16):
    print(''.join('{:02x} '.format(x) for x in v[i * 16:i * 16 + 16]))
