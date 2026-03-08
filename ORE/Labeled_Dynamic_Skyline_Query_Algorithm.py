# Labeled_Dynamic_Skyline_Query_Algorithm.py
import sys
from Secure_Compare import secure_compare


def labeled_dynamic_skyline_query(encrypted_indep, encrypted_q, indep_sum_hash_tables, q3, keys, d, dataset_name):


    S = []  # 存储 original_index
    I = []  # 存储 original_index
    N = encrypted_indep.shape[0]

    label_array = [[] for _ in range(N)]

    # 步骤 2：遍历 encrypted_indep 的每个点
    for i in range(N):
        if not S:
            S.append(i)
            continue
        is_dominated = False
        s_idx = 0
        while s_idx < len(S):
            j = S[s_idx]
            enc_pj = encrypted_indep[j]
            flag_m = [0] * d
            for m in range(d):
                enc_pa_j = encrypted_indep[i, m]
                enc_pb_j = enc_pj[m]
                enc_q_j = encrypted_q[m]
                pair1 = (i, j)
                pair2 = (j, i)
                if pair1 in indep_sum_hash_tables[m]:
                    enc_pa_pb_j, key_idx = indep_sum_hash_tables[m][pair1]
                elif pair2 in indep_sum_hash_tables[m]:
                    enc_pa_pb_j, key_idx = indep_sum_hash_tables[m][pair2]
                else:
                    print(f"Warning: Pair {pair1} or {pair2} not found in hash table for dimension {m}")
                    continue
                enc_2q_j = q3[key_idx - d]  # q3 索引调整
                flag_m[m] = secure_compare(enc_pa_j, enc_pb_j, enc_q_j, enc_pa_pb_j, enc_2q_j, keys[m], keys[key_idx],
                                           m)
            all_flag_ge_0 = True
            exists_flag_gt_0 = False
            for m in range(d):
                if flag_m[m] < 0:
                    all_flag_ge_0 = False
                    break
                if flag_m[m] > 0:
                    exists_flag_gt_0 = True
            if all_flag_ge_0 and exists_flag_gt_0:
                is_dominated = True

                label_array[j].append(i)
                I.append(i)
                break
            all_flag_le_0 = True
            exists_flag_lt_0 = False
            for m in range(d):
                if flag_m[m] > 0:
                    all_flag_le_0 = False
                    break
                if flag_m[m] < 0:
                    exists_flag_lt_0 = True
            if all_flag_le_0 and exists_flag_lt_0:

                label_array[i].append(j)
                S.pop(s_idx)
                I.append(j)
            else:
                s_idx += 1
        if not is_dominated:
            S.append(i)

    S_points = [encrypted_indep[idx] for idx in S]

    return S_points, I, label_array


# 计算 label的内存占用
def get_size(obj, seen=None):
    if seen is None:
        seen = set()
    obj_id = id(obj)
    if obj_id in seen:
        return 0
    seen.add(obj_id)
    size = sys.getsizeof(obj)
    if isinstance(obj, list):
        size += sum(get_size(item, seen) for item in obj)
    elif isinstance(obj, dict):
        size += sum(get_size(k, seen) + get_size(v, seen) for k, v in obj.items())
    return size
