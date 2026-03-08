import random
from paillier import encrypt

def generate_encrypted_points(public_key, d, scale=100, seed=42):
    # 设置随机种子
    if seed is not None:
        random.seed(seed)

    # 生成点 q
    q = [round(random.uniform(0, 1), 2) for _ in range(d)]
    print(f"点 q_int: {q}")
    # 缩放到整数
    q_int = [int(q_j * scale) for q_j in q]


    # 加密 q_int 的每个维度
    E_pk_q_int = [encrypt(public_key, q_j_int) for q_j_int in q_int]

    return q_int, E_pk_q_int