import numpy as np

# 1. indep（独立数据集）
def generate_indep(N, d,precision=2):
    data = np.random.uniform(0, 1, size=(N, d))
    return np.round(data, decimals=precision)

# 2. corr（相关数据集）
def generate_corr(N, d, precision=2):
    data = np.zeros((N, d))
    for i in range(N):
        plane_distance = np.random.normal(loc=0.5, scale=0.2)
        offsets = np.random.normal(loc=0, scale=0.1, size=d)
        data[i] = np.clip(plane_distance + offsets, 0, 1)
    return np.round(data, decimals=precision)

# 3. anti（反相关数据集）- 调整版
def generate_anti(N, d, precision=2):
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

