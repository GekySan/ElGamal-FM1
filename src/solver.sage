# -*- coding: utf-8 -*-

import ctypes
import re
import subprocess
from typing import Optional, Tuple

LOCAL_CHALLENGE_SCRIPT = 'test.sage'

CURVE_PARAMS = {
    'Name': 'secp256k1',
    'A': 0,
    'B': 7,
    'Prime': 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1,
}

P = Zmod(CURVE_PARAMS['Prime'])
EllipticCurve_secp256k1 = EllipticCurve(P, [CURVE_PARAMS['A'], CURVE_PARAMS['B']])


def load_cpp_library(library_path: str) -> ctypes.CDLL:
    cpp_library = ctypes.CDLL(library_path)
    cpp_library.CheckFaultBit.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p,
        ctypes.c_char_p, ctypes.c_char_p,
        ctypes.c_char_p, ctypes.c_char_p,
        ctypes.c_int
    ]
    cpp_library.CheckFaultBit.restype = ctypes.c_int
    return cpp_library

def read_until(proc: subprocess.Popen, expected_bytes: bytes) -> bytes:
    buffer = b''
    while expected_bytes not in buffer:
        chunk = proc.stdout.read(1)
        if not chunk:
            error_output = proc.stderr.read()
            print("--- ERREUR DU PROCESSUS ---")
            print(error_output.decode(errors='ignore'))
            print("---------------------------------")
            raise EOFError("Le processus s'est terminé de manière inattendue.")
        buffer += chunk
    return buffer


def send_line(proc: subprocess.Popen, data_bytes: bytes):
    proc.stdin.write(data_bytes + b'\n')
    proc.stdin.flush()


def get_initial_encryption_local(
    proc: subprocess.Popen,
    known_message: bytes = b"attack_message"
) -> Optional[Tuple[object, object, object]]:
    print('Demande du chiffrement initial...')
    read_until(proc, b'$> ')
    send_line(proc, b'1')
    read_until(proc, b'Plaintext : ')
    send_line(proc, known_message)

    output = read_until(proc, b'[+] Menu:').decode('utf-8', errors='ignore')
    
    m_match = re.search(r"Associed Point: \n\s*X=(\d+)\n\s*Y=(\d+)", output)
    c1_match = re.search(r"C1=\((\d+), (\d+)\)", output)
    c2_match = re.search(r"C2=\((\d+), (\d+)\)", output)

    if not all([m_match, c1_match, c2_match]):
        print("[-] Erreur : Impossible de parser les points chiffrés.")
        return None, None, None
    
    return (
        EllipticCurve_secp256k1(int(m_match.group(1)), int(m_match.group(2))),
        EllipticCurve_secp256k1(int(c1_match.group(1)), int(c1_match.group(2))),
        EllipticCurve_secp256k1(int(c2_match.group(1)), int(c2_match.group(2)))
    )


def get_faulty_decryption_local(proc: subprocess.Popen, c1: object, c2: object) -> Optional[object]:
    payload = f'[({c1.xy()[0]},{c1.xy()[1]});({c2.xy()[0]},{c2.xy()[1]})]'
    read_until(proc, b'$> ')
    send_line(proc, b'3')
    read_until(proc, b'Ciphertext [(x1,y1);(x2,y2)]: ')
    send_line(proc, payload.encode())

    output = read_until(proc, b'[+] Menu:').decode('utf-8', errors='ignore')
    
    match = re.search(r"Associed Point: \n\s*X=(\d+)\n\s*Y=(\d+)", output)
    if not match:
        return None
    
    return EllipticCurve_secp256k1(int(match.group(1)), int(match.group(2)))


def submit_key_local(proc: subprocess.Popen, key: int):
    print('\nSoumission de la clé finale au processus...')
    read_until(proc, b'$> ')
    send_line(proc, b'4')
    read_until(proc, b'Key (int): ')
    send_line(proc, str(key).encode())
    
    response = proc.stdout.read().decode('utf-8', errors='ignore')
    print("\n[+] Réponse du processus :")
    print(response)
    proc.terminate()


def main():
    try:
        cpp_lib = load_cpp_library('./LibFA.so')
    except OSError as e:
        print(f"Impossible de charger la bibliothèque C++.\n{e}")
        return

    print(f"Lancement du processus local : {LOCAL_CHALLENGE_SCRIPT}...")
    with subprocess.Popen(
        ['sage', LOCAL_CHALLENGE_SCRIPT],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    ) as proc:
        
        message_point, c1_point, c2_point = get_initial_encryption_local(proc)
        if message_point is None:
            return

        m_x, m_y = (hex(c)[2:].encode('ascii') for c in message_point.xy())
        c1_x, c1_y = (hex(c)[2:].encode('ascii') for c in c1_point.xy())

        known_bits = {}
        attempts = 0
        key_bit_length = EllipticCurve_secp256k1.order().bit_length()
        print(f'\nDébut de l\'attaque via la bibliothèque C++ ({key_bit_length} bits à trouver)...')
        
        while len(known_bits) < key_bit_length:
            attempts += 1
            
            faulty_message_point = get_faulty_decryption_local(proc, c1_point, c2_point)
            if faulty_message_point is None:
                continue

            mf_x, mf_y = (hex(c)[2:].encode('ascii') for c in faulty_message_point.xy())

            for i in range(key_bit_length):
                if i in known_bits:
                    continue

                result = cpp_lib.CheckFaultBit(m_x, m_y, mf_x, mf_y, c1_x, c1_y, i)

                if result == 0:
                    known_bits[i] = 0
                    print(f'[Essai #{attempts}] Bit {i} trouvé: 0. Progression: {len(known_bits)}/{key_bit_length}')
                    break
                elif result == 1:
                    known_bits[i] = 1
                    print(f'[Essai #{attempts}] Bit {i} trouvé: 1. Progression: {len(known_bits)}/{key_bit_length}')
                    break

        print('\nTous les bits ont été récupérés !')
        recovered_key = 0
        for i in sorted(known_bits.keys()):
            if known_bits[i] == 1:
                recovered_key += (2**i)
                
        print(f'Clé secrète reconstruite : {recovered_key}')
        submit_key_local(proc, recovered_key)

    print("Le processus est terminé.")

if __name__ == '__main__':
    main()
