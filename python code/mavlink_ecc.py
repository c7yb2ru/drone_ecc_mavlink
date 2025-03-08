import xml.etree.ElementTree as ET
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import os

# MAVLink 프로토콜 파일 경로
mavlink_file_path = '/Volumes/One Touch/python code/졸업논문 파이썬 코드/drone_mavlink_protocol_file.xml'

# 암호화된 XML 파일 저장 경로
encrypted_file_path = os.path.join(os.path.dirname(mavlink_file_path), "drone_mavlink_protocol_encrypted_mavlink.xml")

def ecc_encrypt(data):
    # ECC 키 생성
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()

    # PEM 형식으로 변환
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM, #pem 형식으로 인코딩
        format=serialization.PrivateFormat.TraditionalOpenSSL, #openssl 형식
        encryption_algorithm=serialization.NoEncryption() #암호화 없음
    )
    public_pem = public_key.public_bytes( 
        encoding=serialization.Encoding.PEM, #pem 형식으로 인코딩
        format=serialization.PublicFormat.SubjectPublicKeyInfo #공개키 정보
    )
    
    return private_pem, public_pem #개인키, 공개키 반환

def encrypt_mavlink_xml(input_path, output_path): #입력경로, 출력경로
    # XML 파일 로드
    tree = ET.parse(input_path) #xml 파일을 파싱
    root = tree.getroot() #루트 요소를 가져옴
    
    # 메시지 데이터 추출 및 암호화
    for message in root.iter('message'):
        name = message.get('name')
        id = message.get('id')
        
        # 메시지 내용을 ECC 암호화 (id와 name을 단순히 암호화된 텍스트로 치환)
        private_pem, public_pem = ecc_encrypt(f"{name}-{id}")
        
        # XML에 암호화된 데이터 추가
        encrypted_element = ET.SubElement(message, "encrypted") #암호화된 요소 추가
        encrypted_element.text = private_pem.decode('utf-8') #개인키를 문자열로 디코딩하여 저장
        encrypted_element.text = public_pem.decode('utf-8') #공개키를 문자열로 디코딩하여 저장
    
    # 암호화된 XML 저장
    tree.write(output_path, encoding='utf-8', xml_declaration=True) #xml 파일을 저장
    print(f"Encrypted MAVLink XML saved at: {output_path}") 

# 암호화 수행
encrypt_mavlink_xml(mavlink_file_path, encrypted_file_path) # mavlink 파일을 암호화하여 저장

