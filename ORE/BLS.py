import binascii
import secrets
import hashlib
from typing import List
from py_ecc.bls import G2ProofOfPossession as BLS
from py_ecc.optimized_bls12_381 import curve_order


# 计算 SHA-256 哈希
def sha256_hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# 构建 Merkle 树并返回根哈希
def build_merkle_tree(leaves: List[bytes]) -> bytes:

    for leaf in leaves:
        if len(leaf) != 32:
            raise ValueError("Each leaf must be a 32-byte SHA-256 hash.")

    # 如果只有 1 个叶子，直接返回
    if len(leaves) == 1:
        return leaves[0]

    # 如果初始叶子数是奇数，复制最后一个叶子
    current_layer = leaves[:]
    if len(current_layer) % 2 != 0:
        current_layer.append(current_layer[-1])

    # 构建 Merkle 树
    while len(current_layer) > 1:
        next_layer = []
        for i in range(0, len(current_layer), 2):
            parent_hash = sha256_hash(current_layer[i] + current_layer[i + 1])
            next_layer.append(parent_hash)
        # 如果下一层节点数是奇数，复制最后一个节点
        if len(next_layer) % 2 != 0 and len(next_layer) > 1:
            next_layer.append(next_layer[-1])
        current_layer = next_layer

    # 返回根哈希
    return current_layer[0]


# 1. 密钥生成算法（使用安全的随机数生成器）
def key_generation():

    private_key = secrets.randbelow(curve_order - 4) + 1
    public_key = BLS.SkToPk(private_key)
    return private_key, public_key


# 2. 签名算法（对 Merkle 树的根哈希进行签名）
def sign_root(root_hash: bytes, private_key: int):
    # 使用 G2ProofOfPossession 的签名方法对根哈希签名
    signature = BLS.Sign(private_key, root_hash)
    return signature


# 3. 验证算法（验证 Merkle 树的根哈希签名）
def verify_root(root_hash: bytes, signature, public_key):
    # 使用 G2ProofOfPossession 的验证方法
    return BLS.Verify(public_key, root_hash, signature)



def generate_merkle_root_signature(encrypted_data, private_key):
    N, d = encrypted_data.shape
    leaves = []

    for i in range(N):
        concatenated_ciphertext = b''
        for j in range(d):
            left_components, right_components = encrypted_data[i, j]
            for k in range(len(left_components)):
                input_hex, iv_hex = left_components[k]
                left_bytes = binascii.unhexlify(input_hex.replace("0x", ""))
                right_bytes = binascii.unhexlify(right_components[k].replace("0x", ""))
                concatenated_ciphertext += left_bytes + right_bytes
        leaf_hash = sha256_hash(concatenated_ciphertext)
        leaves.append(leaf_hash)


    root_hash = build_merkle_tree(leaves)
    root_signature = sign_root(root_hash, private_key)
    return root_signature


def compute_root_hash(encrypted_data):
    N, d = encrypted_data.shape
    leaves = []
    for i in range(N):
        concatenated = b''
        for j in range(d):
            left_components, right_components = encrypted_data[i, j]
            for k in range(len(left_components)):
                input_hex, iv_hex = left_components[k]
                left_bytes = binascii.unhexlify(input_hex.replace("0x", ""))
                right_bytes = binascii.unhexlify(right_components[k].replace("0x", ""))
                concatenated += left_bytes + right_bytes
        leaves.append(sha256_hash(concatenated))
    if len(leaves) % 2 != 0:
        leaves.append(leaves[-1])
    return build_merkle_tree(leaves)