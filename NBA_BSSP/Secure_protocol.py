from paillier import *
import random


def secure_multiplication(public_key, private_key, E_pk_a, E_pk_b):
    """实现安全乘法协议：SM(E_pk(a), E_pk(b)) -> E_pk(a * b)，使用同态操作"""
    N_squared = public_key.nsquare
    N = public_key.n

    # P1 选择随机数 r
    r = random.randint(1, 5)  # 选择较小的随机数，避免过大指数
    E_pk_r = encrypt(public_key, r)

    # 计算 E_pk(a + r) = E_pk_a * E_pk_r
    E_pk_a_plus_r = (E_pk_a.ciphertext() * E_pk_r.ciphertext()) % N_squared
    E_pk_a_plus_r = paillier.EncryptedNumber(public_key, E_pk_a_plus_r)

    # P2 解密 E_pk_a_plus_r 得到 a + r
    a_plus_r = decrypt(private_key, E_pk_a_plus_r)

    # P2 计算 E_pk((a + r) * b) = E_pk(b)^(a + r)
    E_pk_b_pow_a_plus_r = pow(E_pk_b.ciphertext(), a_plus_r, N_squared)
    E_pk_b_pow_a_plus_r = paillier.EncryptedNumber(public_key, E_pk_b_pow_a_plus_r)

    # P2 计算 E_pk(r * b) = E_pk(b)^r
    E_pk_b_pow_r = pow(E_pk_b.ciphertext(), r, N_squared)
    E_pk_b_pow_r = paillier.EncryptedNumber(public_key, E_pk_b_pow_r)

    # P1 计算 E_pk(a * b) = E_pk((a + r) * b) * E_pk(-r * b)
    # 计算 E_pk(-r * b) = E_pk(r * b)^(-1)
    inv_E_pk_r_b = pow(E_pk_b_pow_r.ciphertext(), N - 1, N_squared)
    E_pk_neg_r_b = paillier.EncryptedNumber(public_key, inv_E_pk_r_b)

    # E_pk(a * b) = E_pk((a + r) * b) * E_pk(-r * b)
    E_pk_a_b = (E_pk_b_pow_a_plus_r.ciphertext() * E_pk_neg_r_b.ciphertext()) % N_squared
    return paillier.EncryptedNumber(public_key, E_pk_a_b)


def secure_minimum(public_key, private_key, E_pk_list):
    """实现安全最小值协议：SMIN(E_pk(a_1), ..., E_pk(a_n)) -> E_pk(min(a_1, ..., a_n))"""
    N = public_key.n
    N_squared = public_key.nsquare

    # 检查输入列表是否至少有两个密文
    if len(E_pk_list) < 2:
        raise ValueError("需要至少两个密文来计算最小值")

    # 步骤 1: C₁ 选择 n 个随机数 r_i，并计算加密值 E_pk(r_i)
    num_random = 10  # C₁ 用于混淆的随机数数量，这里设为 10
    r = [random.randint(1, 5) for _ in range(num_random)]  # 随机生成 num_random 个 r_i
    E_pk_r = [encrypt(public_key, r_i) for r_i in r]  # 加密每个 r_i

    # 步骤 2: C₁ 计算 E_pk(a_j - r_i) 对于每个 a_j 和 r_i
    # Paillier 加密支持同态加法：E_pk(a_j - r_i) = E_pk(a_j) * E_pk(-r_i) = E_pk(a_j) * (E_pk(r_i))^(-1)
    E_pk_minus_r = []
    for E_pk_r_i in E_pk_r:
        # 计算 E_pk(-r_i) = (E_pk(r_i))^(-1) mod N^2
        inv_E_pk_r_i = pow(E_pk_r_i.ciphertext(), N - 1, N_squared)
        E_pk_minus_r.append(paillier.EncryptedNumber(public_key, inv_E_pk_r_i))

    # 计算 E_pk(a_j - r_i) 对于每个 a_j
    E_pk_a_minus_r = []  # 列表，存储每个 a_j 对应的 [E_pk(a_j - r_1), ..., E_pk(a_j - r_num_random)]
    for E_pk_a_j in E_pk_list:
        E_pk_a_j_minus_r = []
        for E_pk_minus_r_i in E_pk_minus_r:
            E_pk_a_j_minus_r_i = (E_pk_a_j.ciphertext() * E_pk_minus_r_i.ciphertext()) % N_squared
            E_pk_a_j_minus_r.append(paillier.EncryptedNumber(public_key, E_pk_a_j_minus_r_i))
        E_pk_a_minus_r.append(E_pk_a_j_minus_r)

    # 步骤 3: C₂ 解密 E_pk(a_j - r_i)，并找到每一组 r_i 对应的最小值
    # 注意：这里我们模拟 C₂ 行为，实际中 C₂ 需与 C₁ 协作，因为 C₂ 没有私钥
    E_pk_min_a_minus_r = []
    for i in range(num_random):
        # 对每个 r_i，解密所有 a_j - r_i
        values_minus_r_i = []
        for j in range(len(E_pk_list)):
            a_j_minus_r_i = decrypt(private_key, E_pk_a_minus_r[j][i])  # a_j - r_i
            values_minus_r_i.append((a_j_minus_r_i, j))  # 记录值和对应的索引 j

        # 找到最小值和对应的索引
        min_value, min_idx = min(values_minus_r_i, key=lambda x: x[0])
        # 取对应的 E_pk(a_j - r_i) 作为这一组的最小值
        E_pk_min_a_minus_r.append(E_pk_a_minus_r[min_idx][i])

    # 步骤 4: C₁ 接收 E_pk(min(a_1 - r_i, ..., a_n - r_i))，并计算 E_pk(min(a_1, ..., a_n))
    # 使用同态性质：E_pk(min(a_1, ..., a_n)) = E_pk(min(a_1 - r_i, ..., a_n - r_i) + r_i)
    E_pk_min_a = []
    for i in range(num_random):
        E_pk_min_i_plus_r_i = (E_pk_min_a_minus_r[i].ciphertext() * E_pk_r[i].ciphertext()) % N_squared
        E_pk_min_a.append(paillier.EncryptedNumber(public_key, E_pk_min_i_plus_r_i))

    # 步骤 5: 返回所有 E_pk(min(a_1, ..., a_n)) 中的一个（理论上它们都相同）
    return E_pk_min_a[0]



def secure_less_than_or_equal(public_key, private_key, E_pk_a, E_pk_b):
    N = public_key.n
    N_squared = public_key.nsquare

    # 计算 E_pk(a - b) = E_pk(a) * E_pk(-b)
    inv_E_pk_b = pow(E_pk_b.ciphertext(), N - 1, N_squared)  # E_pk(-b) = E_pk(b)^(N-1) mod N^2
    E_pk_minus_b = paillier.EncryptedNumber(public_key, inv_E_pk_b)
    E_pk_a_minus_b = (E_pk_a.ciphertext() * E_pk_minus_b.ciphertext()) % N_squared
    E_pk_a_minus_b = paillier.EncryptedNumber(public_key, E_pk_a_minus_b)

    # 选择随机数 r，确保 a - b + r >= 0
    r = random.randint(1, 5)
    E_pk_r = encrypt(public_key, r)
    E_pk_a_minus_b_plus_r = (E_pk_a_minus_b.ciphertext() * E_pk_r.ciphertext()) % N_squared
    E_pk_a_minus_b_plus_r = paillier.EncryptedNumber(public_key, E_pk_a_minus_b_plus_r)

    # 解密 a - b + r
    a_minus_b_plus_r = decrypt(private_key, E_pk_a_minus_b_plus_r)

    # 判断 a - b + r <= r，即 a - b <= 0，即 a <= b
    bool_result = 1 if a_minus_b_plus_r <= r else 0

    # 加密布尔结果
    E_pk_bool = encrypt(public_key, bool_result)
    return E_pk_bool


def secure_and(public_key, private_key, E_pk_a, E_pk_b):

    # 由于 a 和 b 是比特，a AND b = a * b
    # 直接调用 secure_multiplication 来计算 E_pk(a * b)

    E_pk_a_and_b = secure_multiplication(public_key, private_key, E_pk_a, E_pk_b)
    return E_pk_a_and_b


def secure_equal(public_key, private_key, E_pk_a, E_pk_b):

    N = public_key.n
    N_squared = public_key.nsquare

    # 步骤 1: C1 计算 E_pk(a - b) = E_pk(a) * E_pk(-b)
    # 计算 E_pk(-b) = E_pk(b)^(-1) mod N^2
    inv_E_pk_b = pow(E_pk_b.ciphertext(), N - 1, N_squared)
    E_pk_minus_b = paillier.EncryptedNumber(public_key, inv_E_pk_b)
    # 计算 E_pk(a - b) = E_pk(a) * E_pk(-b)
    E_pk_a_minus_b = (E_pk_a.ciphertext() * E_pk_minus_b.ciphertext()) % N_squared
    E_pk_a_minus_b = paillier.EncryptedNumber(public_key, E_pk_a_minus_b)

    # 步骤 2: C1 选择随机数 r != 0
    r = random.randint(1, 5)  # 修改为较小的范围，防止解密溢出
    # 计算 E_pk(r * (a - b)) = E_pk(a - b)^r mod N^2
    E_pk_r_times_a_minus_b = pow(E_pk_a_minus_b.ciphertext(), r, N_squared)
    E_pk_r_times_a_minus_b = paillier.EncryptedNumber(public_key, E_pk_r_times_a_minus_b)

    # 步骤 3: C2 解密 E_pk(r * (a - b))
    r_times_a_minus_b = decrypt(private_key, E_pk_r_times_a_minus_b)
    # 判断 r * (a - b) 是否为 0
    bool_result = 1 if r_times_a_minus_b == 0 else 0

    # 步骤 4: C2 加密判断结果 E_pk(Bool(a == b))
    E_pk_bool = encrypt(public_key, bool_result)
    return E_pk_bool


def secure_less(public_key, private_key, E_pk_a, E_pk_b):

    # Step 1: 计算 E_pk(Bool(a == b)) 使用 SEQ
    E_pk_eq = secure_equal(public_key, private_key, E_pk_a, E_pk_b)

    # Step 2: 计算 E_pk(Bool(a <= b)) 使用 SLEQ
    E_pk_leq = secure_less_than_or_equal(public_key, private_key, E_pk_a, E_pk_b)

    # Step 3: 计算 E_pk(not Bool(a == b)) = E_pk(1 - Bool(a == b))
    # 因为 Bool(a == b) 是 0 或 1，可以用 E_pk(1) * E_pk_eq^{-1}
    E_pk_one = encrypt(public_key, 1)
    N_squared = public_key.nsquare
    inv_E_pk_eq = pow(E_pk_eq.ciphertext(), public_key.n - 1, N_squared)
    E_pk_not_eq = (E_pk_one.ciphertext() * inv_E_pk_eq) % N_squared
    E_pk_not_eq = paillier.EncryptedNumber(public_key, E_pk_not_eq)

    # Step 4: 计算 E_pk(Bool(a < b)) = SM(E_pk_leq, E_pk_not_eq)
    E_pk_less = secure_multiplication(public_key, private_key, E_pk_leq, E_pk_not_eq)

    return E_pk_less