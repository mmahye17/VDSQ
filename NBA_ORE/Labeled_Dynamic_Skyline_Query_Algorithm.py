import sys

from Secure_Compare import secure_compare
from ore import encrypt

def labeled_dynamic_skyline_query(encrypted_indep, encrypted_q, indep_sum_hash_tables, q3, keys, d, dataset_name):
    # 步骤 1：初始化 S 和 I
    S = []  # 存储 (point, original_index) 对
    I = []  # 存储 (point, original_index) 对
    N = encrypted_indep.shape[0]
    label_array = [[] for _ in range(N)]  # 存储每个点的支配点下标列表

    # 步骤 2：遍历 encrypted_indep 的每个点
    for i in range(N):
        if not S:
            S.append((encrypted_indep[i], i))
            continue
        is_dominated = False
        s_idx = 0
        while s_idx < len(S):
            enc_pj, j = S[s_idx]
            flag_m = [0] * d
            has_greater = False
            has_less = False

            # 提前查找哈希表
            pair1 = (i, j)
            pair2 = (j, i)
            pair_found = False
            for m in range(d):
                sum_val = None
                key_idx = None
                if pair1 in indep_sum_hash_tables[m]:
                    sum_val, key_idx = indep_sum_hash_tables[m][pair1]
                    pair_found = True
                elif pair2 in indep_sum_hash_tables[m]:
                    sum_val, key_idx = indep_sum_hash_tables[m][pair2]
                    pair_found = True
                else:
                    print(f"Warning: Pair {pair1} or {pair2} not found in hash table for dimension {m}")
                    continue

                enc_pa_j = encrypted_indep[i, m]  # Enc(p_i[m])
                enc_pb_j = enc_pj[m]  # Enc(p_j[m])
                enc_q_j = encrypted_q[m]  # Enc(q[m])
                enc_2q_j = q3[key_idx - d]  # q3 索引调整
                # [修改]：sum_val 已是密文，直接使用
                enc_pa_pb_j = sum_val
                flag_m[m] = secure_compare(enc_pa_j, enc_pb_j, enc_q_j, enc_pa_pb_j, enc_2q_j, keys[m], keys[key_idx], m)

                # 同时检查大小关系
                if flag_m[m] > 0:
                    has_greater = True
                elif flag_m[m] < 0:
                    has_less = True

            # 如果 pair 未找到，跳过
            if not pair_found:
                s_idx += 1
                continue

            # 如果存在大于和小于，互不支配
            if has_greater and has_less:
                s_idx += 1
                continue

            # [修改]：调整支配关系为 pj[m] >= pi[m] 且存在 pj[m] > pi[m]
            if all(f <= 0 for f in flag_m) and any(f < 0 for f in flag_m):
                # pj 支配 pi（pj[m] >= pi[m] 且存在 pj[m] > pi[m]）
                is_dominated = True
                label_array[j].append(i)  # 记录 pi 的下标到 pj 的 label_array
                I.append((encrypted_indep[i], i))
                break
            elif all(f >= 0 for f in flag_m) and any(f > 0 for f in flag_m):
                # pi 支配 pj
                label_array[i].append(j)  # 记录 pj 的下标到 pi 的 label_array
                removed_point, removed_index = S.pop(s_idx)
                I.append((removed_point, removed_index))
            else:
                # 互不支配（包括相等情况或无法判断的情况）
                s_idx += 1

        if not is_dominated:
            S.append((encrypted_indep[i], i))

    """
    print(f"\n=== Skyline Set (S) for {dataset_name} dataset ===\n")
    print(f"Number of points in S: {len(S)}\n")
    for point, index in S:
        print(f"Point {index}: {point}")
    print(f"\n=== Dominated Set (I) for {dataset_name} dataset ===\n")
    print(f"Number of points in I: {len(I)}\n")
    for point, index in I:
        print(f"Point {index}: {point}")
    """

    """
    print(f"\n=== Label Array for {dataset_name} dataset ===\n")
    for i, labels in enumerate(label_array):
        print(f"Point {i}: Dominated by points {labels}")
    """

    # [新增]：计算 label_array 的内存占用
    def get_size(obj, seen=None):
        """递归计算对象及其内容的内存占用（单位：字节）"""
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

    label_array_size_bytes = get_size(label_array)
    label_array_size_mb = label_array_size_bytes / (1024 * 1024)  # 转换为 MB
    print(f"\nNBA-ORE Memory usage of label_array: {label_array_size_mb:.3f} MB\n")

    return [point for point, _ in S], I, label_array