from paillier import *
from Secure_protocol import secure_less_than_or_equal, secure_and, secure_less


def secure_dominance_protocol(public_key, private_key, E_pk_a, E_pk_b, sk):

    m = len(E_pk_a)  # 向量维度
    N_squared = public_key.nsquare

    # 步骤 1: 初始化 C1 和 C2（这里我们直接在函数中模拟双方的协作）

    # 步骤 2-3: 循环计算 delta_j = E_pk(Bool(a[j] <= b[j])) 使用 SLEQ
    delta = []
    for j in range(m):
        delta_j = secure_less_than_or_equal(public_key, private_key, E_pk_a[j], E_pk_b[j])
        delta.append(delta_j)

    # 步骤 4: 使用 SAND 计算 phi = delta_1 AND ... AND delta_m
    phi = delta[0]
    for j in range(1, m):
        phi = secure_and(public_key, private_key, phi, delta[j])

    # 步骤 5: C1 什么也不做（只是占位说明）

    # 步骤 6-7: 计算 alpha 和 beta
    # alpha = E_pk(a[1] + ... + a[m]), beta = E_pk(b[1] + ... + b[m])
    # 使用 Paillier 加密的同态加法：E_pk(a + b) = E_pk(a) * E_pk(b) mod N^2
    alpha = E_pk_a[0]  # 初始值 E_pk(a[1])
    beta = E_pk_b[0]  # 初始值 E_pk(b[1])
    for j in range(1, m):
        # alpha = E_pk(a[1] + ... + a[j+1])
        alpha = paillier.EncryptedNumber(public_key, (alpha.ciphertext() * E_pk_a[j].ciphertext()) % N_squared)
        # beta = E_pk(b[1] + ... + b[j+1])
        beta = paillier.EncryptedNumber(public_key, (beta.ciphertext() * E_pk_b[j].ciphertext()) % N_squared)

    # 步骤 8-9: 使用 SLESS 计算 sigma = E_pk(Bool(alpha < beta))
    sigma = secure_less(public_key, private_key, alpha, beta)

    # 步骤 10: 计算 psi = sigma AND phi 作为最终支配关系
    psi = secure_and(public_key, private_key, sigma, phi)

    return psi



"""
if __name__ == "__main__":
    # 生成密钥
    public_key, private_key = generate_keys()

    # 测试数据
    a = [1, 2]  # 示例向量 a
    b = [2, 3]  # 示例向量 b
    m = len(a)

    # 加密 a 和 b
    E_pk_a = [encrypt(public_key, a[j]) for j in range(m)]
    E_pk_b = [encrypt(public_key, b[j]) for j in range(m)]

    # 调用协议
    E_pk_psi = secure_dominance_protocol(public_key, private_key, E_pk_a, E_pk_b, private_key)

    # 解密结果
    psi = decrypt(private_key, E_pk_psi)
    print(f"支配关系结果：a < b: {psi}")  # 预期输出 1（true），因为 [1, 2] < [2, 3]
"""