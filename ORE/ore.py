import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes  # [注意]：仅在未修改部分使用，修改部分已移除其使用
import math


def generate_key_array(n, d, key_size=32, seed=42):
    np.random.seed(seed)
    num_keys = math.ceil((2 * n - 3) / 4) * d + d
    key_array = [bytes(np.random.randint(0, 256, key_size, dtype=np.uint8)) for _ in range(num_keys)]
    return key_array


def _split_into_blocks(message, block_size=16, precision=2):
    """将消息（数字字符串，支持浮点数）分割成指定大小的块"""
    num = float(message)
    scaled_num = int(round(num * (10 ** precision)))
    is_negative = scaled_num < 0
    abs_num = abs(scaled_num)
    bin_str = bin(abs_num)[2:]
    bin_len = len(bin_str)
    padded_len = ((bin_len + block_size - 1) // block_size) * block_size
    bin_str = bin_str.zfill(padded_len)
    blocks = [bin_str[i:i + block_size] for i in range(0, len(bin_str), block_size)]
    blocks.insert(0, '1' if is_negative else '0')
    return blocks


def _prf(input_data, key, iv):
    """伪随机函数，使用AES-CBC"""
    padded_input = pad(input_data if isinstance(input_data, bytes) else input_data.encode(), 16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(padded_input)
    byte_length = (16 + 7) // 8
    return encrypted[:byte_length]
    # [未修改]：_prf 逻辑未变


def encrypt(message, key, block_size=16, precision=2, seed=None):
    """ORE加密，返回16进制形式的密文，种子控制随机性"""
    blocks = _split_into_blocks(message, block_size, precision)
    left_components = []
    right_components = []

    # [修改]：设置种子以固定 r 和 iv
    # [新增代码]
    if seed is not None:
        np.random.seed(seed)

    for i, block in enumerate(blocks):
        # [修改]：原 r = get_random_bytes(4) 改为伪随机生成
        # [原始代码]：r = get_random_bytes(4)
        r = bytes(np.random.randint(0, 256, 4, dtype=np.uint8))
        # [修改]：原 iv = get_random_bytes(16) 改为伪随机生成
        # [原始代码]：iv = get_random_bytes(16)
        iv = bytes(np.random.randint(0, 256, 16, dtype=np.uint8))
        left_input = str(i).encode() + r
        left_component = _prf(left_input, key, iv)
        left_components.append((left_input.hex(), iv.hex()))

        block_int = int(block, 2)
        byte_length = (block_size + 7) // 8
        right_component = bytes(a ^ b for a, b in
                                zip(left_component,
                                    block_int.to_bytes(byte_length, 'big')))
        right_components.append(right_component.hex())

    return (left_components, right_components)


def compare(ct1, ct2, key):
    """
    比较两个16进制密文
    返回: -1 (ct1 < ct2), 0 (ct1 = ct2), 1 (ct1 > ct2)
    """
    left1, right1 = ct1
    left2, right2 = ct2

    if len(left1) < len(left2):
        return -1
    elif len(left1) > len(left2):
        return 1

    for i in range(len(left1)):
        input1_hex, iv1_hex = left1[i]
        input2_hex, iv2_hex = left2[i]
        input1 = bytes.fromhex(input1_hex)
        iv1 = bytes.fromhex(iv1_hex)
        input2 = bytes.fromhex(input2_hex)
        iv2 = bytes.fromhex(iv2_hex)

        block1 = bytes(a ^ b for a, b in zip(_prf(input1, key, iv1), bytes.fromhex(right1[i])))
        block2 = bytes(a ^ b for a, b in zip(_prf(input2, key, iv2), bytes.fromhex(right2[i])))
        block1_int = int.from_bytes(block1, 'big')
        block2_int = int.from_bytes(block2, 'big')

        if i == 0:
            if block1_int == 1 and block2_int == 0:
                return -1
            elif block1_int == 0 and block2_int == 1:
                return 1
            elif block1_int == block2_int:
                continue
        if block1_int < block2_int:
            return -1
        elif block1_int > block2_int:
            return 1
    return 0
    # [未修改]：compare 逻辑未变


def decrypt(ciphertext, key, block_size=16, precision=2):
    """解密ORE密文，返回原始浮点数（仅用于调试或特定场景）"""
    left_components, right_components = ciphertext
    blocks = []

    for i in range(len(left_components)):
        input_hex, iv_hex = left_components[i]
        right_hex = right_components[i]
        input_data = bytes.fromhex(input_hex)
        iv = bytes.fromhex(iv_hex)
        right_data = bytes.fromhex(right_hex)

        left_component = _prf(input_data, key, iv)
        block_bytes = bytes(a ^ b for a, b in zip(left_component, right_data))
        block_int = int.from_bytes(block_bytes, 'big')

        if i == 0:
            is_negative = block_int == 1
        else:
            block_bin = bin(block_int)[2:].zfill(block_size)
            blocks.append(block_bin)

    bin_str = ''.join(blocks)
    num_int = int(bin_str, 2)
    num = num_int / (10 ** precision)
    return -num if is_negative else num
    # [未修改]：decrypt 逻辑未变



