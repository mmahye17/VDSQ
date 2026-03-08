import gc

from matplotlib import pyplot as plt

from datas import *
import numpy as np
from BLS import generate_merkle_root_signature, key_generation, compute_root_hash, verify_root
from enc_q import generate_encrypted_points
from ore import generate_key_array

np.random.seed(42)
N = 1000
d = 3


indep_data = generate_indep(N, d)

"""
corr_data = generate_corr(N, d)
"""
"""
anti_data = generate_anti(N, d)
"""

"""
# 获取数据点个数
indep_count = indep_data.shape[0]
corr_count = corr_data.shape[0]
anti_count = anti_data.shape[0]

# 打印结果
print(f"indep_data 的数据点个数: {indep_count}")
print(f"corr_data 的数据点个数: {corr_count}")
print(f"anti_data 的数据点个数: {anti_count}")

# 可视化（仅适用于 d=2 的情况）
def plot_data(data, title):
    plt.scatter(data[:, 0], data[:, 1], s=10, alpha=0.5)
    plt.title(title)
    plt.xlabel('Dimension 1')
    plt.ylabel('Dimension 2')
    plt.xlim(0, 1)
    plt.ylim(0, 1)
    plt.grid(True)
    plt.show()

# 绘制三种数据集的散点图
if d == 2:
    plot_data(indep_data, 'Independent Dataset')
    plot_data(corr_data, 'Correlated Dataset')
    plot_data(anti_data, 'Anti-Correlated Dataset')
"""



keys = generate_key_array(N, d)
print(f"\n生成的密钥数量: {len(keys)}\n")
"""
print(f"密钥数组: {[k.hex() for k in keys]}")
"""

q, encrypted_q, q1, q3 = generate_encrypted_points(N, d, seed=42, keys=keys)



encrypted_indep = encrypt_dataset(indep_data, keys)

"""
encrypted_corr = encrypt_dataset(corr_data, keys)
"""
"""
encrypted_anti = encrypt_dataset(anti_data, keys)
"""


"""
private_key, public_key = key_generation()
print("\n=== BLS Key Pair ===")
print(f"Private Key: {hex(private_key)[2:]}")
print(f"Public Key: {public_key.hex()}")
"""



"""
root_hash_indep = compute_root_hash(encrypted_indep)
root_hash_corr = compute_root_hash(encrypted_corr)
root_hash_anti = compute_root_hash(encrypted_anti)
"""


"""
indep_root_signature = generate_merkle_root_signature(encrypted_indep, private_key)
corr_root_signature = generate_merkle_root_signature(encrypted_corr, private_key)
anti_root_signature = generate_merkle_root_signature(encrypted_anti, private_key)
"""



"""
print("\n=== Root Signatures ===\n")
print(f"Indep Root Signature: {indep_root_signature.hex()} (Verified: {verify_root(root_hash_indep, indep_root_signature, public_key)})")
print(f"Corr Root Signature: {corr_root_signature.hex()} (Verified: {verify_root(root_hash_corr, corr_root_signature, public_key)})")
print(f"Anti Root Signature: {anti_root_signature.hex()} (Verified: {verify_root(root_hash_anti, anti_root_signature, public_key)})\n")
"""




indep_avl_trees = build_avl_tree_for_dataset(indep_data, "Indep", keys, d)

"""
corr_avl_trees = build_avl_tree_for_dataset(corr_data, "Corr", keys, d)
"""
"""
anti_avl_trees = build_avl_tree_for_dataset(anti_data, "Anti", keys, d)
"""





indep_for_sum = store_plaintext_and_index_for_sum(indep_data, d)

"""
corr_for_sum = store_plaintext_and_index_for_sum(corr_data, d)
"""
"""
anti_for_sum = store_plaintext_and_index_for_sum(anti_data, d)
"""


del indep_avl_trees, q1, q
del indep_data
gc.collect()
print("\nMemory cleared for indep_avl_trees and indep_data\n")


"""
del corr_avl_trees, q1, q
del corr_data
gc.collect()
print("\nMemory cleared for corr_avl_trees and corr_data\n")
"""

"""
del anti_avl_trees, q1, q
del anti_data
gc.collect()
print("\nMemory cleared for anti_avl_trees and anti_data\n")
"""






indep_sum_hash_tables = build_sum_hash_tables(indep_for_sum, "Indep", keys, N, d)

"""
corr_sum_hash_tables = build_sum_hash_tables(corr_for_sum, "Corr", keys, N, d)
"""
"""
anti_sum_hash_tables = build_sum_hash_tables(anti_for_sum, "Anti", keys, N, d)
"""