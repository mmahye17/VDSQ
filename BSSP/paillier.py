from phe import paillier



"""
def generate_keys():
    public_key, private_key = paillier.generate_paillier_keypair()
    return public_key, private_key
"""


def generate_keys(n_length=256):
    #生成并返回Paillier公钥和私钥，n_length 指定 N 的位数
    public_key, private_key = paillier.generate_paillier_keypair(n_length=n_length)
    return public_key, private_key


def print_keys(public_key, private_key):
    """打印公钥和私钥"""
    print(f"公钥 (Public Key): N = {public_key.n}")
    print(f"私钥 (Private Key): p = {private_key.p}, q = {private_key.q}")


def encrypt(public_key, plaintext):
    """加密明文"""
    return public_key.encrypt(plaintext)


def decrypt(private_key, ciphertext):
    """解密密文"""
    return private_key.decrypt(ciphertext)


def homomorphic_addition(public_key, E_pk_a, E_pk_b):
    """验证加法同态性质：D_sk(E_pk(a) × E_pk(b) mod N^2) = (a + b) mod N"""
    N = public_key.n
    N_squared = public_key.nsquare

    # 计算 E_pk(a) × E_pk(b) mod N^2
    E_pk_a_plus_b = (E_pk_a.ciphertext() * E_pk_b.ciphertext()) % N_squared

    # 返回 paillier.EncryptedNumber 对象
    return paillier.EncryptedNumber(public_key, E_pk_a_plus_b)


def homomorphic_scalar_multiplication(public_key, private_key, E_pk_a, k):
    """验证标量乘法性质：D_sk(E_pk(a)^k mod N^2) = k × a mod N"""
    N = public_key.n
    N_squared = public_key.nsquare

    # 计算 E_pk(a)^k mod N^2
    E_pk_a_k = pow(E_pk_a.ciphertext(), k, N_squared)

    return E_pk_a_k


"""
if __name__ == "__main__":
    # 生成密钥
    public_key, private_key = generate_keys()

    # 打印公钥和私钥
    print_keys(public_key, private_key)

    # 测试数据
    a = 15
    b = 25
    k = 3

    # 验证加法同态
    homomorphic_addition(public_key, private_key, a, b)

    # 验证标量乘法
    homomorphic_scalar_multiplication(public_key, private_key, a, k)
"""
