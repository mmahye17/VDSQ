from ore import compare

def secure_compare(enc_pa_j, enc_pb_j, enc_q_j, enc_pa_pb_j, enc_2q_j, key1, key2, m):
    # [修改]：调整比较逻辑以支持新的支配关系（pj[m] >= pi[m] 且存在 pj[m] > pi[m]）
    cmp = compare(enc_pa_j, enc_pb_j, key1)
    if cmp == 0:
        return 0  # pa_j == pb_j
    elif cmp == -1:  # pa_j < pb_j
        # 检查是否满足 |q[m] - pa_j| < |q[m] - pb_j|
        if compare(enc_q_j, enc_pa_j, key1) == 1 and compare(enc_pb_j, enc_q_j, key1) == 1:
            # |q[m] - pa_j| < |q[m] - pb_j| 等价于 2q[m] < pa_j + pb_j
            return -compare(enc_2q_j, enc_pa_pb_j, key2)  # [修改]：反转比较结果
        else:
            return 1  # [修改]：pa_j < pb_j，返回 1 表示 pb_j > pa_j
    else:  # cmp == 1, pa_j > pb_j
        # 检查是否满足 |q[m] - pa_j| > |q[m] - pb_j|
        if compare(enc_q_j, enc_pa_j, key1) == -1 and compare(enc_pb_j, enc_q_j, key1) == -1:
            # |q[m] - pa_j| > |q[m] - pb_j| 等价于 pa_j + pb_j < 2q[m]
            return -compare(enc_pa_pb_j, enc_2q_j, key2)  # [修改]：反转比较结果
        else:
            return -1  # [修改]：pa_j > pb_j，返回 -1 表示 pb_j < pa_j