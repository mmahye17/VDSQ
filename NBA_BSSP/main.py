import gc
import time
import pandas as pd
import numpy as np

from Basic_Secure_Skyline_Protocol import basic_secure_skyline_protocol
from Secure_Dominance_Protocol import secure_dominance_protocol
from datas import *
from Secure_protocol import *
from enc_datas import preprocess
from enc_q import generate_encrypted_points
from paillier import generate_keys, print_keys, encrypt, decrypt

np.random.seed(42)
# 定义数据集大小和维度，可随意修改
N = 2000  # 数据点数量
d = 3     # 数据维度

# 读取 Excel 文件（假设文件名为 'data.xlsx'，包含 2500 行 6 列的数据）
# 数据值在 [-10000, 0] 范围内
excel_file = 'data1.xlsx'  # 请确保 Excel 文件路径正确
data_df = pd.read_excel(excel_file, header=None)  # 假设 Excel 无表头
# 确保 N 和 d 不超过 Excel 数据的行数和列数
N = min(N, data_df.shape[0])  # 动态调整 N
d = min(d, data_df.shape[1])  # 动态调整 d
# 截取前 N 行和前 d 列
indep_data_int = data_df.iloc[:N, :d].values.astype(int)
print("\n从 Excel 文件读取数据集完成\n")

# 生成公私钥
public_key, private_key = generate_keys()
print_keys(public_key, private_key)

# 生成加密的 q_int 和 E_pk_q_int，q 的值在 [-10000, 0] 范围内
q_int, E_pk_q_int = generate_encrypted_points(public_key, d, min_val=-10000, max_val=0, seed=42)


# 加密数据集
E_pk_indep = [[encrypt(public_key, int(indep_data_int[i][j])) for j in range(d)] for i in range(N)]
print("\n加密数据集E_pk_indep完成\n")

# 调用 preprocess 函数处理加密的 indep_data
E_pk_T_indep = preprocess(public_key, private_key, E_pk_indep, E_pk_q_int)
print("\n加密数据集E_pk_indep的preprocess完成\n")

# 清内存
del q_int, E_pk_q_int
gc.collect()
print("\nMemory cleared for indep\n")

# BSSP
start_time = time.time()
skyline1 = basic_secure_skyline_protocol(public_key, private_key, E_pk_indep, E_pk_T_indep, private_key, d)
end_time = time.time()
elapsed_time = end_time - start_time
print(f"indep动态天际线运行时间: {elapsed_time:.8f} 秒\n")
skyline1_float = [[val for val in point] for point in skyline1]  # 去掉 scale 后直接使用整数值
print(f"indep天际线结果: {skyline1_float}")

"""
# 生成corr数据集
corr_data = generate_corr(N, d)
print("\ncorr数据集完成生成\n")

# 将数据缩放为整数
corr_data_int = (corr_data * scale).round().astype(int)
print("\ncorr数据集缩放完成\n")

del corr_data
gc.collect()

# 加密数据集
E_pk_corr = [[encrypt(public_key, int(corr_data_int[i][j])) for j in range(d)] for i in range(N)]
print("\n加密数据集E_pk_corr完成\n")

del corr_data_int
gc.collect()

# 调用 preprocess 函数处理加密的 corr_data
E_pk_T_corr = preprocess(public_key, private_key, E_pk_corr, E_pk_q_int)
print("\n加密数据集E_pk_corr的preprocess完成\n")

#清内存
del q_int, E_pk_q_int
gc.collect()
print("\nMemory cleared for corr\n")

# BSSP
start_time = time.time()
skyline2 = basic_secure_skyline_protocol(public_key, private_key, E_pk_corr, E_pk_T_corr, private_key, d)
end_time = time.time()
elapsed_time = end_time - start_time
print(f"corr动态天际线运行时间: {elapsed_time:.8f} 秒\n")
skyline2_float = [[round(val / scale, 5) for val in point] for point in skyline2]
print(f"corr天际线结果: {skyline2_float}")
"""

"""
# 生成anti数据集
anti_data = generate_anti(N, d)
print("\nanti数据集完成生成\n")

# 将数据缩放为整数
anti_data_int = (anti_data * scale).round().astype(int)
print("\nanti数据集缩放完成\n")

del anti_data
gc.collect()

# 加密数据集
E_pk_anti = [[encrypt(public_key, int(anti_data_int[i][j])) for j in range(d)] for i in range(N)]
print("\n加密数据集E_pk_anti完成\n")

del anti_data_int
gc.collect()

# 调用 preprocess 函数处理加密的 anti_data
E_pk_T_anti = preprocess(public_key, private_key, E_pk_anti, E_pk_q_int)
print("\n加密数据集E_pk_anti的preprocess完成\n")

#清内存
del q_int, E_pk_q_int
gc.collect()
print("\nMemory cleared for anti\n")

# BSSP
start_time = time.time()
skyline3 = basic_secure_skyline_protocol(public_key, private_key, E_pk_anti, E_pk_T_anti, private_key, d)
end_time = time.time()
elapsed_time = end_time - start_time
print(f"anti动态天际线运行时间: {elapsed_time:.8f} 秒\n")
skyline3_float = [[round(val / scale, 5) for val in point] for point in skyline3]
print(f"anti天际线结果: {skyline3_float}")
"""

# 测试
"""
# 测试secure_multiplication
E_pk_result = secure_multiplication(public_key, private_key, E_pk_a, E_pk_b)
result = decrypt(private_key, E_pk_result)
print(f"安全乘法结果：解密后的值 = {result}")
"""

"""
# 测试secure_minimum
E_pk_list = [encrypt(public_key, x) for x in [10, 7, 15, 3, 20]]  # 示例：加密多个值
E_pk_min = secure_minimum(public_key, private_key, E_pk_list)
result = decrypt(private_key, E_pk_min)
print(f"安全最小值结果：解密后的值 = {result}")
"""

"""
#测试secure_less_than_or_equal
E_pk_bool = secure_less_than_or_equal(public_key, private_key, E_pk_a, E_pk_b)
result = decrypt(private_key, E_pk_bool)
print(f"SLEQ 结果：解密后的值 = {result}, 预期 a <= b: {a <= b}")
"""

"""
# 测试secure_and
E_pk_and = secure_and(public_key, private_key, E_pk_a, E_pk_b)
result = decrypt(private_key, E_pk_and)
print(f"SAND 结果：解密后的值 = {result}, 预期 a AND b: {a & b}")
"""

"""
# 测试secure_equal
E_pk_bool = secure_equal(public_key, private_key, E_pk_a, E_pk_b)
result = decrypt(private_key, E_pk_bool)
print(f"SEQ 结果: {result}, 预期: {1 if a == b else 0}")
"""

"""
# 测试secure_less
E_pk_less = secure_less(public_key, private_key, E_pk_a, E_pk_b)
result = decrypt(private_key, E_pk_less)
print(f"SLESS 结果：解密后的值 = {result}, 预期 a < b: {a < b}")
"""