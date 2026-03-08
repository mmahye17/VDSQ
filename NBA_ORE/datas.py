import math
import numpy as np

from AVL_Tree import AVLTree
from cantor import cantor_pairing
from ore import encrypt, generate_key_array


# 1. indep（独立数据集）
def generate_indep(N, d,precision=5):
    """
    生成独立数据集，每个维度的值独立且均匀分布在 [0, 1) 之间。
    """
    data = np.random.uniform(0, 1, size=(N, d))
    return np.round(data, decimals=precision)

# 2. corr（相关数据集）
def generate_corr(N, d, precision=5):
    """
    生成相关数据集，数据点沿对角线分布，具有正相关性。
    """
    data = np.zeros((N, d))
    for i in range(N):
        plane_distance = np.random.normal(loc=0.5, scale=0.2)
        offsets = np.random.normal(loc=0, scale=0.1, size=d)
        data[i] = np.clip(plane_distance + offsets, 0, 1)
    return np.round(data, decimals=precision)

# 3. anti（反相关数据集）- 调整版
def generate_anti(N, d, precision=5):
    """
    生成反相关数据集，点靠近通过 (0.5, ..., 0.5) 的平面，平面内属性值均匀分布。
    使用稍大的方差使点分布更分散，同时保持反相关性。
    """
    data = np.zeros((N, d))
    for i in range(N):
        # 使用稍大的方差正态分布选择平面距离，靠近 0.5
        plane_distance = np.random.normal(loc=0.5, scale=0.04)  # 调整方差从 0.01 到 0.1
        # 第一个维度在 [0, 1) 内均匀分布
        base_value = np.random.uniform(0, 1)
        # 计算剩余维度的总和，使点靠近平面 (0.5, ..., 0.5)
        target_sum = d * plane_distance  # 平面总和
        remaining_sum = target_sum - base_value  # 剩余维度总和
        if d > 1:
            # 在剩余 d-1 个维度中均匀分配 remaining_sum
            remaining_values = np.random.uniform(0, 1, size=d-1)
            remaining_values = remaining_values / remaining_values.sum() * remaining_sum
            data[i, 0] = base_value
            data[i, 1:] = np.clip(remaining_values, 0, 1)
        else:
            data[i, 0] = base_value  # 一维情况直接赋值
    return np.round(data, decimals=precision)


# 按维度排序并分离为 d 个数据库
def sort_by_dimensions(data, d):
    sorted_dims = []
    for dim in range(d):
        sorted_dim = np.sort(data[:, dim])
        sorted_dims.append(sorted_dim)
    return sorted_dims


# 加密数据集
def encrypt_dataset(data, key_array):
    N, d = data.shape
    if len(key_array) < d:
        raise ValueError("密钥数组长度不足，至少需要 d 个密钥")
    encrypted_data = np.empty((N, d), dtype=object)
    for j in range(d):
        for i in range(N):
            value_str = str(data[i, j])
            encrypted_data[i, j] = encrypt(value_str, key_array[j])
    return encrypted_data


# 为单个数据集建立 AVL 树
def build_avl_tree_for_dataset(dataset, dataset_name, keys, d):
    avl_trees = []
    if len(keys) < d:
        raise ValueError(f"密钥数组长度 {len(keys)} 不足，至少需要 {d} 个密钥")
    ore_keys = keys[:d]
    N = dataset.shape[0]
    for j in range(d):
        dim_data = dataset[:, j]
        tree = AVLTree(ore_instance=ore_keys[j])
        # 插入明文，index 为原始数据集下标
        for i in range(N):
            tree.insert_plaintext(float(dim_data[i]), index=i)
        tree.encrypt_plaintexts()
        avl_trees.append(tree)
        print(f"{dataset_name} 数据集的第 {j + 1} 维的 AVL 树已建好，树索引：{len(avl_trees) - 1}")
    return avl_trees





def store_plaintext_and_index_for_sum(data, d):
    """为每个数据集的每个维度分别存储 plaintext 和 index"""
    # [修改]：检查 data 是否为 numpy 数组
    if not isinstance(data, np.ndarray):
        raise TypeError(f"Expected data to be a numpy.ndarray, but got {type(data)}")

    # [修改]：确保 data 是二维数组
    if data.ndim != 2 or data.shape[1] != d:
        raise ValueError(f"Expected data to be a 2D array with {d} columns, but got shape {data.shape}")

    for_sum = []
    print("\n提取数据集的 plaintext 和 index，按 plaintext 升序排序")
    for dim in range(d):
        # 获取该维度的所有值和对应的下标
        plaintexts = data[:, dim].tolist()
        indices = list(range(len(data)))
        # 将 plaintexts 和 indices 配对并按 plaintexts 升序排序
        paired = list(zip(plaintexts, indices))
        paired.sort(key=lambda x: x[0])
        sorted_plaintexts, sorted_indices = zip(*paired)
        for_sum.append([list(sorted_plaintexts), list(sorted_indices)])
        print(f"第 {dim + 1} 维: {len(sorted_plaintexts)} plaintexts, {len(sorted_indices)} indices")
    return for_sum


# 构建和对哈希表
def build_sum_hash_tables(for_sum, dataset_name, keys, n, d):
    """为一个数据集的每个维度构建和对哈希表"""
    keys_per_db = math.ceil((2 * n - 3) / 4)
    hash_tables = [{} for _ in range(d)]
    key_offset = d
    for dim in range(d):
        plaintexts = for_sum[dim][0]
        indices = for_sum[dim][1]
        alpha = list(zip(plaintexts, indices))
        c = 0
        while alpha:
            key_idx = key_offset + dim * keys_per_db + c
            if len(alpha) >= 2:
                first_val, first_idx = alpha[0]
                for i in range(1, len(alpha)):
                    sum_val = first_val + alpha[i][0]
                    sum_idx = cantor_pairing(first_idx, alpha[i][1])
                    # [修改]：将 sum_val 加密为密文
                    sum_val_enc = encrypt(f"{sum_val:.10f}", keys[key_idx])
                    hash_tables[dim][(first_idx, alpha[i][1])] = (sum_val_enc, key_idx)
            if len(alpha) >= 3:
                last_val, last_idx = alpha[-1]
                for i in range(1, len(alpha) - 1):
                    sum_val = last_val + alpha[i][0]
                    sum_idx = cantor_pairing(last_idx, alpha[i][1])
                    # [修改]：将 sum_val 加密为密文
                    sum_val_enc = encrypt(f"{sum_val:.10f}", keys[key_idx])
                    hash_tables[dim][(last_idx, alpha[i][1])] = (sum_val_enc, key_idx)
            print(f"{dataset_name} 数据集的第 {dim + 1} 维的第 {c + 1} 轮和对哈希表已更新")
            if len(alpha) > 2:
                alpha = alpha[1:-1]
            else:
                alpha = []
            c += 1
    return hash_tables