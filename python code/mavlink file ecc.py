from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os
import base64
import xml.etree.ElementTree as ET

def generate_key_pair():
    """ ECC 공개/개인 키 쌍 생성 """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    """ 공개 키를 직렬화하여 반환 """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def derive_shared_secret(private_key, peer_public_key):
    """ ECC를 이용한 공유 비밀 키 계산 """
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'key agreement'
    ).derive(shared_secret)
    return derived_key

def encrypt_message(message, key):
    """ 간단한 XOR 암호화 (데모용) """
    encrypted = bytes([b ^ key[i % len(key)] for i, b in enumerate(message.encode())])
    return base64.b64encode(encrypted).decode()

def decrypt_message(encrypted_message, key):
    """ XOR 암호화 복호화 """
    encrypted = base64.b64decode(encrypted_message)
    decrypted = bytes([b ^ key[i % len(key)] for i, b in enumerate(encrypted)])
    return decrypted.decode()

def process_mavlink_xml(input_path, output_path, key):
    """ MAVLink XML 메시지를 암호화하여 저장 """
    tree = ET.parse(input_path)
    root = tree.getroot()
    
    for message in root.iter('message'):
        name = message.get('name')
        id = message.get('id')
        encrypted_text = encrypt_message(f"{name}-{id}", key)
        
        encrypted_element = ET.SubElement(message, "encrypted")
        encrypted_element.text = encrypted_text
    
    tree.write(output_path, encoding='utf-8', xml_declaration=True)
    print(f"Encrypted MAVLink XML saved at: {output_path}")

# 입력 및 출력 파일 경로 설정
input_xml_path = "/Volumes/One Touch/python code/졸업논문 파이썬 코드/drone_mavlink_protocol_file.xml"
output_xml_path = "/Volumes/One Touch/python code/졸업논문 파이썬 코드/drone_mavlink_protocol_encrypted_mavlink.xml"
# 1. 비밀 키 및 공개 키 생성
server_private, server_public = generate_key_pair()
controller_private, controller_public = generate_key_pair()
drone_private, drone_public = generate_key_pair()

# 2. 공개 키 교환 (네트워크 상 공개됨)
server_public_bytes = serialize_public_key(server_public)
controller_public_bytes = serialize_public_key(controller_public)
drone_public_bytes = serialize_public_key(drone_public)

# 3. 비밀 키 값 공유 (ECDH 방식)
server_shared_key = derive_shared_secret(server_private, controller_public)
controller_shared_key = derive_shared_secret(controller_private, server_public)
drone_shared_key = derive_shared_secret(drone_private, server_public)

# 4. XML 파일 암호화 및 저장
process_mavlink_xml(input_xml_path, output_xml_path, server_shared_key)