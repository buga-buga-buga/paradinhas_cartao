#!/usr/bin/env python3
"""
HSM Thales PayShield - Cálculo de Chave Criptografada

Este script simula o processo de criptografia de uma chave (ex: CVK/CSCK) 
sob LMK, seguindo o padrão do HSM Thales PayShield, incluindo aplicação de variants 
e cálculo de Key Check Value (KCV).

Ideal para estudos, troubleshooting e validação de processos de importação de chaves.
"""

from Crypto.Cipher import DES3
import binascii

def hex_to_bytes(hex_str):
    """Converte uma string hexadecimal para bytes."""
    return binascii.unhexlify(hex_str)

def bytes_to_hex(data):
    """Converte bytes para uma string hexadecimal maiúscula."""
    return binascii.hexlify(data).decode().upper()

def apply_key_type_variant(lmk_left, lmk_right, variant_id):
    """
    Aplica o variant_id no primeiro byte do LMK LEFT.
    Exemplo: Variant 4 = 0xDE (usado para CVK/CSCK).
    Retorna LMK LEFT modificado e LMK RIGHT inalterado.
    """
    variant_map = {
        0: 0x00,  # Sem variant
        1: 0xA6,
        2: 0x5A,
        3: 0x6A,
        4: 0xDE,  # Usado para CVK/CSCK
        5: 0x2B,
        6: 0x50,
        7: 0x74,
        8: 0x9C,
        9: 0xFA,
    }
    
    if variant_id == 0:
        return lmk_left[:], lmk_right[:]  # Sem alteração
    
    variant_value = variant_map.get(variant_id, 0x00)
    
    # Aplica XOR no primeiro byte do LMK LEFT
    modified_left = bytearray(lmk_left)
    modified_left[0] ^= variant_value
    
    return bytes(modified_left), lmk_right[:]

def encrypt_under_variant_lmk(input_key, lmk_left, lmk_right, scheme_tag):
    """
    Criptografa a chave de entrada sob LMK modificado, usando o esquema 'U' (double-length).
    Para cada metade da chave, aplica um variant diferente no LMK RIGHT.
    """
    if scheme_tag == 'U':
        if len(input_key) != 16:
            raise ValueError("Double-length key necessária para o scheme U")
        scheme_variants = [0xA6, 0x5A]  # Variants padrão do scheme U
    else:
        raise ValueError(f"Unknown scheme tag: {scheme_tag}")
    
    encrypted = bytearray()
    
    for i, scheme_variant in enumerate(scheme_variants):
        # Monta LMK para este segmento (LEFT + RIGHT)
        variant_lmk = bytearray(16)
        variant_lmk[:8] = lmk_left
        variant_lmk[8:16] = lmk_right
        
        # Aplica o variant no primeiro byte do LMK RIGHT
        variant_lmk[8] ^= scheme_variant
        
        # Cria chave 3DES (K1-K2-K1)
        triple_des_key = bytes(variant_lmk) + bytes(variant_lmk[:8])
        
        # Criptografa 8 bytes do segmento da chave
        cipher = DES3.new(triple_des_key, DES3.MODE_ECB)
        segment = input_key[i*8:(i+1)*8]
        encrypted_segment = cipher.encrypt(segment)
        encrypted.extend(encrypted_segment)
    
    return bytes(encrypted)

def calculate_thales_payshield_key():
    """
    Simula o cálculo da chave criptografada sob LMK, conforme o HSM Thales PayShield.
    Mostra passo a passo do processo, incluindo aplicação de variants e análise detalhada.
    """
    print("=== CÁLCULO THALES PAYSHIELD ===\n")
    
    # 1. Dados de entrada (exemplo de CVK double-length)
    clear_key = "0123456789012345ABCDEF0123456789"
    key_type_code = "402"  # CVK/CSCK
    scheme_tag = 'U'       # Esquema double-length
    
    print(f"Chave original: {clear_key}")
    print(f"Key Type: {key_type_code} (CVK/CSCK)")
    print(f"Scheme: {scheme_tag}")
    
    # 2. Detalhes do tipo de chave (exemplo baseado em tabela Go)
    # "402": {Name: "CVK/CSCK", Code: "402", LMKPair: 7, VariantID: 4}
    lmk_pair_index = 7    # LMK 14-15
    variant_id = 4        # Variant 4 = 0xDE
    
    print(f"LMK Pair Index: {lmk_pair_index} (LMK 14-15)")
    print(f"Variant ID: {variant_id}")
    
    # 3. LMKs originais (exemplo)
    lmk_14 = "E0E0010101010101"
    lmk_15 = "F1F1010101010101"
    
    print(f"\nLMK 14 (original): {lmk_14}")
    print(f"LMK 15 (original): {lmk_15}")
    
    lmk_14_bytes = hex_to_bytes(lmk_14)
    lmk_15_bytes = hex_to_bytes(lmk_15)
    
    # 4. Aplica o variant do tipo de chave no LMK LEFT
    modified_lmk_14, modified_lmk_15 = apply_key_type_variant(
        lmk_14_bytes, lmk_15_bytes, variant_id
    )
    
    print(f"\nApós aplicar Variant {variant_id} (0xDE):")
    print(f"LMK 14 modificado: {bytes_to_hex(modified_lmk_14)}")
    print(f"LMK 15 (inalterado): {bytes_to_hex(modified_lmk_15)}")
    
    # Verificação do XOR aplicado
    print(f"Verificação: 0xE0 XOR 0xDE = 0x{0xE0 ^ 0xDE:02X}")
    
    # 5. Prepara a chave de entrada (em bytes)
    input_key_bytes = hex_to_bytes(clear_key)
    
    print(f"\nChave de entrada ({len(input_key_bytes)} bytes): {bytes_to_hex(input_key_bytes)}")
    
    # 6. Criptografa a chave sob LMK modificado, usando o scheme U
    encrypted_key = encrypt_under_variant_lmk(
        input_key_bytes, 
        modified_lmk_14, 
        modified_lmk_15, 
        scheme_tag
    )
    
    print(f"\n=== PROCESSO DE ENCRIPTAÇÃO ===")
    print(f"Scheme '{scheme_tag}' usa variants: [0xA6, 0x5A]")
    print(f"Cada variant encripta 8 bytes da chave")
    
    # 7. Monta resultado final (scheme tag + chave criptografada)
    result = scheme_tag + bytes_to_hex(encrypted_key)

    # 8. Análise detalhada dos segmentos
    print(f"\n=== ANÁLISE DETALHADA ===")
    cvk_a = clear_key[:16]
    cvk_b = clear_key[16:]
    encrypted_a = bytes_to_hex(encrypted_key[:8])
    encrypted_b = bytes_to_hex(encrypted_key[8:16])
    
    print(f"CVK A: {cvk_a} -> {encrypted_a}")
    print(f"CVK B: {cvk_b} -> {encrypted_b}")
    
    # 9. Mostra os LMKs usados para cada segmento (com variants)
    print(f"\n=== VARIANTS DE SCHEME ===")
    base_lmk = modified_lmk_14 + modified_lmk_15
    
    # Para primeiro segmento (variant 0xA6)
    variant_1 = bytearray(base_lmk)
    variant_1[8] ^= 0xA6
    print(f"LMK para CVK A (variant 0xA6): {bytes_to_hex(variant_1)}")
    
    # Para segundo segmento (variant 0x5A)
    variant_2 = bytearray(base_lmk)
    variant_2[8] ^= 0x5A
    print(f"LMK para CVK B (variant 0x5A): {bytes_to_hex(variant_2)}")
    
    return result

def calculate_kcv(key_hex):
    """
    Calcula o Key Check Value (KCV) de uma chave.
    O KCV é obtido criptografando 8 bytes zero com a chave e pegando os 6 primeiros hex.
    """
    key_bytes = hex_to_bytes(key_hex)
    zeros = b'\x00' * 8
    
    if len(key_bytes) == 16:
        # Double-length key - usa 3DES (K1-K2-K1)
        triple_key = key_bytes + key_bytes[:8]
        cipher = DES3.new(triple_key, DES3.MODE_ECB)
    else:
        cipher = DES3.new(key_bytes, DES3.MODE_ECB)
    
    encrypted = cipher.encrypt(zeros)
    return bytes_to_hex(encrypted)[:6]

if __name__ == "__main__":
    # Executa o cálculo principal e mostra resultados
    result = calculate_thales_payshield_key()
    
    print(f"\n=== RESULTADO FINAL ===")
    print(f"Chave criptografada: {result}")
    print(f"Esperado:           UC68879EF8F0E22A2B8A51FE73409DC16")
    print(f"Match? {result == 'UC68879EF8F0E22A2B8A51FE73409DC16'}")
    
    # Calcula e mostra o KCV da chave original
    original_key = "0123456789012345ABCDEF0123456789"
    kcv = calculate_kcv(original_key)
    print(f"\n=== KEY CHECK VALUE ===")
    print(f"KCV calculado: {kcv}")
    print(f"KCV esperado:  7FFC84")
    print(f"KCV Match? {kcv == '7FFC84'}")