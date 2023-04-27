import binascii

from toyecc import *
from toyecc.Random import *
from config import *
from utils import *

LICENSE_HEADER = '-----BEGIN MIKROTIK SOFTWARE KEY------------'
LICENSE_FOOTER = '-----END MIKROTIK SOFTWARE KEY--------------'

licensePayload = bytearray(16)
encodedSoftwareIdBytes = encode_software_id(LICENSE_SOFTWARE_ID).to_bytes(6, 'little')
for i in range(5):
  licensePayload[i] = encodedSoftwareIdBytes[i]

licensePayload[6] = LICENSE_ROUTEROS_VERSION
licensePayload[7] = LICENSE_LEVEL

curve = getcurvebyname('curve25519')

privateKey = int(PRIVATE_KEY, 16)
publicKey = privateKey * curve.G

print('Public key:')
print(hex(int.from_bytes(int(publicKey.x).to_bytes(32, 'big'), 'little'))[2:])
print()

while True:
  nonceSecret = secure_rand_int_between(1, curve.n - 1)
  noncePoint = nonceSecret * curve.G
  nonce = int(noncePoint.x) % curve.n
  nonceHash = mikro_sha256(nonce.to_bytes(32, 'little'))

  licensePayloadHash = mikro_sha256(licensePayload)

  for i in range(16):
    licensePayloadHash[8 + i] ^= nonceHash[i]

  licensePayloadHash[0] &= 0xF8
  licensePayloadHash[31] &= 0x7F
  licensePayloadHash[31] |= 0x40

  licensePayloadHashInt = int.from_bytes(licensePayloadHash, 'little')

  signature = pow(privateKey, -1, curve.n) * (nonceSecret - licensePayloadHashInt)
  signature %= curve.n

  calculatedNonce = int((publicKey * signature + curve.G * licensePayloadHashInt).x)
  if calculatedNonce == nonce:
    break

encoded = mikro_base64_encode(encode_license_payload(licensePayload) + nonceHash[:16] + signature.to_bytes(32, 'little'), True)

print(LICENSE_HEADER)
print(encoded[:len(LICENSE_HEADER)])
print(encoded[len(LICENSE_HEADER):])
print(LICENSE_FOOTER)
