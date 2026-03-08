import math
import random

from ore import generate_key_array, encrypt


def generate_encrypted_points(n, d, seed=None, keys=None):
    # 设置随机种子
    if seed is not None:
        random.seed(seed)

    # 生成点 q
    q = [round(random.uniform(0, 1), 2) for _ in range(d)]
    print(f"点 q: {q}")

    # 对 q 的每个维度使用前 d 个密钥加密
    encrypted_q = []
    for j in range(d):
        ciphertext = encrypt(str(q[j]), keys[j])
        encrypted_q.append(ciphertext)
    print(f"加密后的 q: {encrypted_q}")

    # 生成 q1，将 q 的每个维度乘以 2
    q1 = [x * 2 for x in q]
    """
    print(f"点 q1: {q1}")
    """

    # 计算剩余密钥数量
    num_remaining_keys = math.ceil((2 * n - 3) / 4) * d
    """
    print(f"剩余密钥数量: {num_remaining_keys}")
    """

    # 对 q1 的每个维度使用剩余密钥加密，生成 q3
    q3 = []
    remaining_keys = keys[d:]  # 去掉前 d 个密钥
    for j in range(d):
        for k in range(math.ceil((2 * n - 3) / 4)):
            key_index = d + j * math.ceil((2 * n - 3) / 4) + k
            if key_index < len(keys):  # 确保不超出密钥数组长度
                ciphertext = encrypt(str(q1[j]), keys[key_index])
                q3.append(ciphertext)

    print(f"q3 包含的密文数量: {len(q3)}")
    """
    print(f"加密后的 q3: {q3}")
    """

    return q, encrypted_q, q1, q3