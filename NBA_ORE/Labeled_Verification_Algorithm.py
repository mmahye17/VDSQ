# Labeled_Verification_Algorithm.py
from Secure_Compare import secure_compare
from ore import compare, encrypt

def labeled_verification(S, I, label_array, encrypted_indep, encrypted_q, indep_sum_hash_tables, q3, keys, d, dataset_name):
    N = len(encrypted_indep)
    temp1 = [0] * N
    temp2 = [0] * N
    temp3 = [0] * len(I)

    for i, (enc_pi, pi_idx) in enumerate(I):
        temp1[:] = [0] * N  # 重置 temp1
        temp2[:] = [0] * N  # 重置 temp2

        for j in range(N):
            if pi_idx in label_array[j]:
                if pi_idx == j:
                    return False

                enc_pj = encrypted_indep[j]
                flag_m = [0] * d
                pair_found = False
                for m in range(d):
                    pair1 = (pi_idx, j)
                    pair2 = (j, pi_idx)
                    sum_val = None
                    key_idx = None
                    if pair1 in indep_sum_hash_tables[m]:
                        sum_val, key_idx = indep_sum_hash_tables[m][pair1]
                        pair_found = True
                    elif pair2 in indep_sum_hash_tables[m]:
                        sum_val, key_idx = indep_sum_hash_tables[m][pair2]
                        pair_found = True
                    else:
                        continue

                    enc_pa_j = enc_pi[m]
                    enc_pb_j = enc_pj[m]
                    enc_q_j = encrypted_q[m]
                    enc_2q_j = q3[key_idx - d]
                    # [修改]：sum_val 已是密文，直接使用
                    enc_pa_pb_j = sum_val
                    flag_m[m] = secure_compare(enc_pa_j, enc_pb_j, enc_q_j, enc_pa_pb_j, enc_2q_j, keys[m], keys[key_idx], m)

                if not pair_found:
                    continue

                # [修改]：调整支配关系为 pj[m] >= pi[m] 且存在 pj[m] > pi[m]
                if all(f <= 0 for f in flag_m) and any(f < 0 for f in flag_m):
                    temp1[j] = 1
                else:
                    return False
            else:
                temp2[j] = 1

        if sum(temp1) > 0 and sum(temp2) < N:
            temp3[i] = 1

    if sum(temp3) != len(I):
        print(f"\n{dataset_name} 数据集的验证结果: False")
        return False
    print(f"\n{dataset_name} 数据集的验证结果: True")
    return True