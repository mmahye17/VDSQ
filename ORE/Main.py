import os
import sys
import time
from Labeled_Dynamic_Skyline_Query_Algorithm import labeled_dynamic_skyline_query, get_size
from Labeled_Verification_Algorithm import labeled_verification
from enc_data import *

d = 3

# 获取桌面路径
desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
output_file = os.path.join(desktop_path, "output.txt")

# 保存原始 stdout
original_stdout = sys.stdout

# 打开文件并重定向 stdout
with open(output_file, "w", encoding="utf-8") as f:
    sys.stdout = f  # 重定向 print 输出到文件


    start_time = time.time()
    S1, I1, label_array1 = labeled_dynamic_skyline_query(
        encrypted_indep, encrypted_q, indep_sum_hash_tables, q3,  keys, d, "indep"
    )
    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"indep标签动态天际线运行时间: {elapsed_time:.8f} 秒\n")


    start_time = time.time()
    result1 = labeled_verification(
        S1, I1, label_array1, encrypted_indep, encrypted_q, indep_sum_hash_tables, q3, keys, d, dataset_name="indep"
    )
    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"indep标签验证运行时间: {elapsed_time:.8f} 秒\n")


    label_array_size_bytes = get_size(label_array1)
    label_array_size_mb = label_array_size_bytes / (1024 * 1024)  # 转换为 MB
    print(f"\nindep Memory usage of label_array: {label_array_size_mb:.8f} MB\n")


    """
    start_time = time.time()
    S2, I2, label_array2 = labeled_dynamic_skyline_query(
        encrypted_corr, encrypted_q, corr_sum_hash_tables, q3,  keys, d, "corr"
    )
    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"corr标签动态天际线运行时间: {elapsed_time:.8f} 秒\n")

    start_time = time.time()
    result1 = labeled_verification(
        S2, I2, label_array2, encrypted_corr, encrypted_q, corr_sum_hash_tables, q3, keys, d, dataset_name="corr"
    )
    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"corr标签验证运行时间: {elapsed_time:.8f} 秒\n")

    label_array_size_bytes = get_size(label_array2)
    label_array_size_mb = label_array_size_bytes / (1024 * 1024)  # 转换为 MB
    print(f"\ncorr Memory usage of label_array: {label_array_size_mb:.8f} MB\n")
    """

    """
    start_time = time.time()
    S3, I3, label_array3 = labeled_dynamic_skyline_query(
        encrypted_anti, encrypted_q, anti_sum_hash_tables, q3,  keys, d, "anti"
    )
    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"anti标签动态天际线运行时间: {elapsed_time:.8f} 秒\n")

    start_time = time.time()
    result1 = labeled_verification(
        S3, I3, label_array3, encrypted_anti, encrypted_q, anti_sum_hash_tables, q3, keys, d, dataset_name="anti"
    )
    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"anti标签验证运行时间: {elapsed_time:.8f} 秒\n")

    label_array_size_bytes = get_size(label_array3)
    label_array_size_mb = label_array_size_bytes / (1024 * 1024)  # 转换为 MB
    print(f"\nanti Memory usage of label_array: {label_array_size_mb:.8f} MB\n")
"""

# 恢复原始 stdout
sys.stdout = original_stdout