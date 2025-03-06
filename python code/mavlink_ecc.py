import pymavlink
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ecc
from cryptography.hazmat.primitives import serialization

def ecc(data):
    private_key = ecc.generate_private_key(ecc.SECP256R1(), default_backend())
    pulic_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM, # 네트워크 암호화 통신을 위한 PEM 형식
        format=serialization.PrivateFormat.TraditionalOpenSSL, # OpenSSL에서 사용하는 형식
        encryption_algorithm=serialization.NoEncryption() #암호화 알고리즘 없음
    )
    public_pem = pulic_key.public_bytes( # 공개키를 바이트로 변환
        encoding=serialization.Encoding.PEM, # 네트워크 암호화 통신을 위한 PEM 형식
        format=serialization.PublicFormat.SubjectPublicKeyInfo # 공개키 정보 형식
    )

def mavlintk(data):
    mavlintk.__module__ = 'pymavlink' # pymavlink 모듈을 사용
    mav = pymavlink.MAVLink(data) # mavlink 데이터를 mav에 저장
    mav.pack() # mav 데이터를 패킹
    mav.get_crc() # mav 데이터의 CRC를 가져옴
    mav.get_magic() # mav 데이터의 magic number를 가져옴
    mav.get_header() # mav 데이터의 header를 가져옴
    mav.get_payload() # mav 데이터의 payload를 가져옴
    mav.get_msgId() # mav 데이터의 message id를 가져옴
    mav.get_payload_crc() # mav 데이터의 payload crc를 가져옴
    mav.get_crc_extra() # mav 데이터의 crc extra를 가져옴
    mav.get_payload_crc_extra() # mav 데이터의 payload crc extra를 가져옴

