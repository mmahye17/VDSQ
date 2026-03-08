from Labeled_Dynamic_Skyline_Query_Algorithm import labeled_dynamic_skyline_query
from Labeled_Verification_Algorithm import labeled_verification
from enc_data import *
import time



start_time = time.time()
S1, I1, label_array1 = labeled_dynamic_skyline_query(
    encrypted_indep, encrypted_q, indep_sum_hash_tables, q3,  keys, d, "indep"
)
end_time = time.time()
elapsed_time = end_time - start_time
print(f"NBA-ORE标签动态天际线运行时间: {elapsed_time:.8f} 秒\n")


start_time = time.time()
result1 = labeled_verification(
    S1, I1, label_array1, encrypted_indep, encrypted_q, indep_sum_hash_tables, q3, keys, d, dataset_name="indep"
)
end_time = time.time()
elapsed_time = end_time - start_time
print(f"NBA-ORE标签验证运行时间: {elapsed_time:.8f} 秒\n")



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
"""