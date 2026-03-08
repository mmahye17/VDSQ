from phe import paillier
from Secure_protocol import secure_multiplication

def preprocess(public_key, private_key, Epk_P, Epk_q):

    N = public_key.n
    N_squared = public_key.nsquare
    n = len(Epk_P)  # 点的数量
    m = len(Epk_P[0])  # 维度数量

    # 步骤 1: 客户端已经发送了 Epk(-q[j])，这里我们假设 Epk_q 是加密的 q[j]
    # 我们需要计算 Epk(-q[j])，即 (Epk(q[j]))^(-1) mod N^2
    Epk_minus_q = []
    for j in range(m):
        inv_Epk_q_j = pow(Epk_q[j].ciphertext(), N - 1, N_squared)
        Epk_minus_q.append(paillier.EncryptedNumber(public_key, inv_Epk_q_j))

    # 步骤 2: C1 计算 Epk(temp[i][j]) = Epk(P[i][j] - q[j])
    Epk_temp = []
    for i in range(n):
        Epk_temp_i = []
        for j in range(m):
            Epk_P_ij_minus_qj = (Epk_P[i][j].ciphertext() * Epk_minus_q[j].ciphertext()) % N_squared
            Epk_temp_i.append(paillier.EncryptedNumber(public_key, Epk_P_ij_minus_qj))
        Epk_temp.append(Epk_temp_i)

    # 步骤 3: C1 和 C2 使用 SM 协议计算 Epk(T[i][j]) = Epk(temp[i][j] × temp[i][j])
    Epk_T = []
    for i in range(n):
        Epk_T_i = []
        for j in range(m):
            # 使用 secure_multiplication 计算 Epk(temp[i][j]^2)
            Epk_T_ij = secure_multiplication(public_key, private_key, Epk_temp[i][j], Epk_temp[i][j])
            Epk_T_i.append(Epk_T_ij)
        Epk_T.append(Epk_T_i)

    return Epk_T


