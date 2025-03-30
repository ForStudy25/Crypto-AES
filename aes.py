import argparse
import sys
import pathlib


S_BOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]
INV_S_BOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]
R_CON = [
    [0x00, 0x00, 0x00, 0x00],
    [0x01, 0x00, 0x00, 0x00],
    [0x02, 0x00, 0x00, 0x00],
    [0x04, 0x00, 0x00, 0x00],
    [0x08, 0x00, 0x00, 0x00],
    [0x10, 0x00, 0x00, 0x00],
    [0x20, 0x00, 0x00, 0x00],
    [0x40, 0x00, 0x00, 0x00],
    [0x80, 0x00, 0x00, 0x00],
    [0x1B, 0x00, 0x00, 0x00],
    [0x36, 0x00, 0x00, 0x00]
]


def sub_bytes(state: list[list[int]]) -> None:
    for r in range(len(state)):
        state[r] = [S_BOX[state[r][c]] for c in range(len(state[0]))]


def sub_bytes_2(state):
    return [[S_BOX[byte] for byte in word] for word in state]


def shift_rows(state: list[list[int]]):
    state[0][1], state[1][1], state[2][1], state[3][1] = state[1][1], state[2][1], state[3][1], state[0][1]
    state[0][2], state[1][2], state[2][2], state[3][2] = state[2][2], state[3][2], state[0][2], state[1][2]
    state[0][3], state[1][3], state[2][3], state[3][3] = state[3][3], state[0][3], state[1][3], state[2][3]


def xtime(a: int) -> int:
    if a & 0x80:
        return ((a << 1) ^ 0x1b) & 0xff
    return a << 1


def mix_column(col: list[int]):
    c_0 = col[0]
    all_xor = col[0] ^ col[1] ^ col[2] ^ col[3]

    # c0 = xtime(c0) ^ xtime(c1) ^ c1 ^ c2 ^ c3
    # c0 = xtime(c0 ^ c1) ^ c1 ^ c2 ^ c3
    # c0 ^= xtime(c0 ^ c1) ^ all_xor
    col[0] ^= xtime(col[0] ^ col[1]) ^ all_xor

    # c1 = xtime(c1 ^ c2) ^ c0 ^ c2 ^ c3
    col[1] ^= xtime(col[1] ^ col[2]) ^ all_xor
                    
    # c2 = xtime(c2 ^ c3) ^ c0 ^ c1 ^ c3
    col[2] ^= xtime(col[2] ^ col[3]) ^ all_xor

    # c3 = xtime(c0 ^ c3) ^ c0 ^ c1 ^ c2
    col[3] ^= xtime(c_0 ^ col[3]) ^ all_xor


def mix_columns(state: list[list[int]]):
    for r in state:
        mix_column(r)


def add_round_key(state: list[list[int]], key_schedule: list[list[list[int]]], round: int):
    round_key = key_schedule[round]
    for r in range(len(state)):
        state[r] = [state[r][c] ^ round_key[r][c] for c in range(len(state[0]))]


def rot_word(word: list[int]) -> list[int]:
    return word[1:] + word[:1]


def sub_word(word: list[int]) -> bytes:
    return bytes(S_BOX[i] for i in word)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes([x ^ y for (x, y) in zip(a, b)])


def key_expansion(key: bytes, nb: int = 4) -> list[list[list[int]]]:
    nk = len(key) // 4

    key_bit_length = len(key) * 8

    if key_bit_length == 128:
        nr = 10
    elif key_bit_length == 192:
        nr = 12
    elif key_bit_length == 256:
        nr = 14
    else:
        raise Exception

    w = state_from_bytes(key)

    for i in range(nk, nb * (nr + 1)):
        temp = w[i-1]
        if i % nk == 0:
            temp = xor_bytes(sub_word(rot_word(temp)), R_CON[i // nk])
        elif nk > 6 and i % nk == 4:
            temp = sub_word(temp)
        w.append(xor_bytes(w[i-nk], temp))
    
    return [w[i * 4:(i + 1) * 4] for i in range(len(w) // 4)]


def state_from_bytes(data: bytes) -> list[list[int]]:
    return [data[i * 4:(i + 1) * 4] for i in range(len(data) // 4)]


def bytes_from_state(state: list[list[int]]) -> bytes:
    return bytes(state[0] + state[1] + state[2] + state[3])


def aes_encrypt(data: bytes, key: bytes) -> bytes:
    state = state_from_bytes(data)
    key_schedule = key_expansion(key)
    key_bit_length = len(key) * 8

    if key_bit_length == 128:
        nr = 10
    elif key_bit_length == 192:
        nr = 12
    elif key_bit_length == 256:
        nr = 14
    else:
        raise Exception
    
    add_round_key(state, key_schedule, 0)

    for round in range(1, nr):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, key_schedule, round)
    
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, key_schedule, round=nr)

    enc_bytes = bytes_from_state(state)
    return enc_bytes


def inv_sub_bytes(state: list[list[int]]):
    for r in range(len(state)):
        state[r] = [INV_S_BOX[state[r][c]] for c in range(len(state[0]))]


def inv_shift_rows(state: list[list[int]]):
    state[1][1], state[2][1], state[3][1], state[0][1] = state[0][1], state[1][1], state[2][1], state[3][1]
    state[2][2], state[3][2], state[0][2], state[1][2] = state[0][2], state[1][2], state[2][2], state[3][2]
    state[3][3], state[0][3], state[1][3], state[2][3] = state[0][3], state[1][3], state[2][3], state[3][3]


def xtimes_0e(b: int) -> int:
    # 0x0e = 0b1110 = ((x * 2 + x) * 2 + x) * 2
    return xtime(xtime(xtime(b) ^ b) ^ b)


def xtimes_0b(b: int) -> int:
    return xtime(xtime(xtime(b)) ^ b) ^ b


def xtimes_0d(b: int) -> int:
    return xtime(xtime(xtime(b) ^ b)) ^ b


def xtimes_09(b: int) -> int:
    return xtime(xtime(xtime(b))) ^ b


def inv_mix_column(col: list[int]):
    c_0, c_1, c_2, c_3 = col[0], col[1], col[2], col[3]

    col[0] = xtimes_0e(c_0) ^ xtimes_0b(c_1) ^ xtimes_0d(c_2) ^ xtimes_09(c_3)
    col[1] = xtimes_09(c_0) ^ xtimes_0e(c_1) ^ xtimes_0b(c_2) ^ xtimes_0d(c_3)
    col[2] = xtimes_0d(c_0) ^ xtimes_09(c_1) ^ xtimes_0e(c_2) ^ xtimes_0b(c_3)
    col[3] = xtimes_0b(c_0) ^ xtimes_0d(c_1) ^ xtimes_09(c_2) ^ xtimes_0e(c_3)


def inv_mix_columns(state: list[list[int]]):
    for r in state:
        inv_mix_column(r)


def aes_decrypt(data: bytes, key: bytes) -> bytes:
    state = state_from_bytes(data)
    key_schedule = key_expansion(key)
    key_bit_length = len(key) * 8

    if key_bit_length == 128:
        nr = 10
    elif key_bit_length == 192:
        nr = 12
    elif key_bit_length == 256:
        nr = 14
    else:
        raise Exception
    
    add_round_key(state, key_schedule, nr)

    for round in range(nr - 1, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, key_schedule, round)
        inv_mix_columns(state)
    
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, key_schedule, round=0)

    enc_bytes = bytes_from_state(state)
    return enc_bytes


def aes_ecb_encrypt(data: bytes, key: bytes) -> bytes:
    result = b""
    for i in range(0, len(data), 16):
        result += aes_encrypt(data[i:i + 16], key)
    return result


def aes_ecb_decrypt(data: bytes, key: bytes) -> bytes:
    result = b""
    for i in range(0, len(data), 16):
        result += aes_decrypt(data[i:i + 16], key)
    return result 


def check_key(key: bytes) -> None:
    key_bit_length = len(key) * 8

    if key_bit_length == 128:
        print("Ключ соответствует формату AES-128")
    elif key_bit_length == 192:
        print("Ключ соответствует формату AES-192")
    elif key_bit_length == 256:
        print("Ключ соответствует формату AES-256")
    else:
        raise ValueError("Введен ключ неверного размера!")


def padding_data(data: bytes, block_size: int = 16) -> None:
    # Добавляет данные по стандарту PKCS7
    padding_length = block_size - (len(data)) % block_size
    padding = bytes([padding_length] * padding_length)
    return data + padding
        

def unpad_data(data: bytes) -> bytes:
    # Удаляет дополнение PKCS7
    padding_length = data[-1]
    if padding_length > len(data) or not all(b == padding_length for b in data[-padding_length:]):
        raise ValueError("Некоректное дополнение PKCS#7")
    return data[:-padding_length]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", required=True, type=str, help="Путь до файла с данными")
    parser.add_argument("-o", "--output", required=True, type=str, help="Путь до файла, куда будет записан результат")
    parser.add_argument("-k", "--key", required=True, type=str, help="Ключ формате")
    parser.add_argument("-m", "--mode", required=True, type=str, help="Режим работы шифрования или расшифровки, принимает значения [\"encrypt\", \"decrypt\"]")
    known_args, _ = parser.parse_known_args(sys.argv)

    key = known_args.key.encode()
    check_key(key)

    mode = known_args.mode
    if mode not in ["encrypt", "decrypt"]:
        print("Выбран неизвестный режим работы!")
        sys.exit(-5)

    in_path = pathlib.Path(known_args.input)
    out_path = pathlib.Path(known_args.output)
    
    data = b""

    if not in_path.exists():
        print(f"Файл {in_path} не найден!")
        sys.exit(-2)
    
    if not in_path.is_file():
        print(f"Объект {in_path} не является файлом!")
        sys.exit(-3)
    
    try:
        with open(in_path.__str__(), "rb") as f:
            data = f.read()
    except:

        print(f"Ошибка чтения файла {in_path}!")
        sys.exit(-4)

    result = b""
    try:
        if mode == "encrypt":
            p_data = padding_data(data)
            result = aes_ecb_encrypt(p_data, key)
            print(f"Encrypt: {result.hex()}")
        elif mode == "decrypt":
            result = aes_ecb_decrypt(data, key)
            result = unpad_data(result)
            print(f"Decrypt: {result.hex()}")
    except:
        print("Возникла ошибка в ходе работы программы!")
        sys.exit(-6)

    try:
        with open(out_path, "wb") as f:
            f.write(result)
    except:
        print(f"Ошибка при записи результата в файл {out_path}!")
        sys.exit(-7)
    
    if mode == "encrypt":
        print("Шифрование успешно завершено!")
    elif mode == "decrypt":
        print("Расшифровка успешно завершена!")
    print(f"Результат записан в файл {out_path}")


if __name__ == "__main__":
    main()
