import random
from paillier import encrypt

def generate_encrypted_points(public_key, d, min_val=-10000, max_val=0, seed=42):
    # 设置随机种子
    if seed is not None:
        random.seed(seed)

    # 生成点 q，在 [min_val, max_val] 范围内
    q_int = [random.randint(min_val, max_val) for _ in range(d)]
    print(f"点 q_int: {q_int}")

    # 加密 q_int 的每个维度
    E_pk_q_int = [encrypt(public_key, q_j_int) for q_j_int in q_int]

    return q_int, E_pk_q_int