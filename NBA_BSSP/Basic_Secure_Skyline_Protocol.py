import random
from Secure_Dominance_Protocol import secure_dominance_protocol
from Secure_protocol import secure_minimum, secure_multiplication
from paillier import encrypt, decrypt, paillier, homomorphic_addition


def basic_secure_skyline_protocol(public_key, private_key, E_pk_P, E_pk_T, sk, d):
    # 算法 4: 基本安全天际线协议
    # 输入: C1 有 E_pk(P), E_pk(T), C2 有 sk
    # 输出: 客户端知道天际线查询结果

    N = public_key.n
    N_squared = public_key.nsquare

    # 检查 E_pk_T 是否为空
    if len(E_pk_T) == 0:
        return []

    # 计算 E_pk(S[i]) = E_pk(T[i][1] + ... + T[i][m]) mod N^2
    E_pk_S = []
    for i in range(len(E_pk_T)):
        E_pk_S_i = E_pk_T[i][0]  # 初始值 E_pk(T[i][1])
        for j in range(1, d):
            E_pk_S_i = homomorphic_addition(public_key, E_pk_S_i, E_pk_T[i][j])
        E_pk_S.append(E_pk_S_i)

    C1_skyline_pool = []
    # 循环直到 E_pk_T 为空
    while len(E_pk_T) > 1:
        # 使用 SMIN 协议计算 E_pk(S(min)) = SMIN(E_pk(S(1)), ..., E_pk(S(n)))
        E_pk_S_min = secure_minimum(public_key, private_key, E_pk_S)

        # 计算 alpha_i = E_pk(S[i] - S(min))，并混淆
        alpha = []
        inv_E_pk_S_min = pow(E_pk_S_min.ciphertext(), N - 1, N_squared)
        E_pk_minus_S_min = paillier.EncryptedNumber(public_key, inv_E_pk_S_min)
        for i in range(len(E_pk_S)):
            E_pk_alpha_i = (E_pk_S[i].ciphertext() * E_pk_minus_S_min.ciphertext()) % N_squared
            E_pk_alpha_i = paillier.EncryptedNumber(public_key, E_pk_alpha_i)
            r = random.randint(1, 50)
            E_pk_r_alpha_i = pow(E_pk_alpha_i.ciphertext(), r, N_squared)
            E_pk_r_alpha_i = paillier.EncryptedNumber(public_key, E_pk_r_alpha_i)
            alpha.append(E_pk_r_alpha_i)

        # C2 解密 alpha_i，找到第一个等于 0 的索引
        for i in range(len(alpha)):
            alpha_i_dec = decrypt(private_key, alpha[i])
            if alpha_i_dec == 0:
                idx = i
                C1_skyline_pool.append(E_pk_P[idx])
                # Store E_pk_T[idx] before modifying the list
                E_pk_T_idx = E_pk_T[idx]
                # Process dominance and deletions
                for j in range(len(E_pk_T) - 1, -1, -1):
                    if idx != j:
                        E_pk_dom = secure_dominance_protocol(public_key, private_key, E_pk_T_idx, E_pk_T[j],
                                                             private_key)
                        dom_result = decrypt(private_key, E_pk_dom)
                        if dom_result == 1:  # E_pk_T_idx dominates E_pk_T[j]
                            del E_pk_T[j]
                            del E_pk_P[j]
                            del E_pk_S[j]
                    elif idx == j:  # Remove the element itself
                        del E_pk_T[j]
                        del E_pk_P[j]
                        del E_pk_S[j]
                break

    # 当 E_pk_T 只剩一个点时，将对应的 E_pk_P 加入天际线池
    if len(E_pk_T) == 1:
        C1_skyline_pool.append(E_pk_P[0])

    # C1: 为每个天际线点添加随机数 r[i][j]
    r = []
    alpha_ij = []
    for i in range(len(C1_skyline_pool)):
        r_i = []
        alpha_i = []
        for j in range(d):
            r_ij = random.randint(1, 50)
            r_i.append(r_ij)
            E_pk_r_ij = encrypt(public_key, r_ij)
            E_pk_alpha_ij = (C1_skyline_pool[i][j].ciphertext() * E_pk_r_ij.ciphertext()) % N_squared
            alpha_i.append(paillier.EncryptedNumber(public_key, E_pk_alpha_ij))
        r.append(r_i)
        alpha_ij.append(alpha_i)

    # C2: 解密 α[i][j] 得到 r'[i][j]
    r_prime = []
    for i in range(len(alpha_ij)):
        r_prime_i = []
        for j in range(d):
            r_prime_ij = decrypt(private_key, alpha_ij[i][j])
            r_prime_i.append(r_prime_ij)
        r_prime.append(r_prime_i)

    # 客户端：计算 P[i][j] = r'[i][j] - r[i][j]
    skyline = []
    for i in range(len(C1_skyline_pool)):
        skyline_point = []
        for j in range(d):
            P_ij = r_prime[i][j] - r[i][j]
            skyline_point.append(P_ij)
        skyline.append(skyline_point)

    return skyline
