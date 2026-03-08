# Labeled_Verification_Algorithm.py
from Secure_Compare import secure_compare
from ore import compare

def labeled_verification(S, I, label_array, encrypted_indep, encrypted_q, indep_sum_hash_tables, q3, keys, d, dataset_name):
    temp1 = [0] * len(encrypted_indep)
    temp2 = [0] * len(encrypted_indep)
    temp3 = [0] * len(I)
    for i in range(len(I)):
        pi_idx = I[i]
        enc_pi = encrypted_indep[pi_idx]
        temp1 = [0] * len(encrypted_indep)
        temp2 = [0] * len(encrypted_indep)
        for j in range(len(encrypted_indep)):

            if pi_idx in label_array[j]:
                if pi_idx == j:
                    return False
                enc_pj = encrypted_indep[j]
                flag_m = [0] * d
                for m in range(d):
                    enc_pa_j = enc_pi[m]
                    enc_pb_j = enc_pj[m]
                    enc_q_j = encrypted_q[m]
                    pair1 = (pi_idx, j)
                    pair2 = (j, pi_idx)
                    if pair1 in indep_sum_hash_tables[m]:
                        enc_pa_pb_j, key_idx = indep_sum_hash_tables[m][pair1]
                    elif pair2 in indep_sum_hash_tables[m]:
                        enc_pa_pb_j, key_idx = indep_sum_hash_tables[m][pair2]
                    else:
                        continue
                    enc_2q_j = q3[key_idx - d]
                    flag_m[m] = secure_compare(enc_pa_j, enc_pb_j, enc_q_j, enc_pa_pb_j, enc_2q_j, keys[m], keys[key_idx], m)
                all_flag_ge_0 = True
                exists_flag_gt_0 = False
                for m in range(d):
                    if flag_m[m] < 0:
                        all_flag_ge_0 = False
                        break
                    if flag_m[m] > 0:
                        exists_flag_gt_0 = True
                if all_flag_ge_0 and exists_flag_gt_0:
                    temp1[j] = 1
                else:
                    return False
            else:
                temp2[j] = 1
        if sum(temp1) != 0 and sum(temp2) != len(encrypted_indep):
            temp3[i] = 1
    if sum(temp3) != len(I):
        print(f"\n{dataset_name} 数据集的验证结果: False")
        return False
    print(f"\n{dataset_name} 数据集的验证结果: True")
    return True