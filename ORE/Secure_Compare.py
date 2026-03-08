from ore import compare

def secure_compare(enc_pa_j, enc_pb_j, enc_q_j, enc_pa_pb_j, enc_2q_j, key1, key2, m):
    if compare(enc_pa_j, enc_pb_j, key1) == 0:
        return 0
    elif compare(enc_pa_j, enc_pb_j, key1) == -1:
        if compare(enc_q_j, enc_pa_j, key1) == 1 and compare(enc_pb_j,enc_q_j, key1) == 1 :
            return compare(enc_2q_j, enc_pa_pb_j, key2)
        else:
            return compare(enc_q_j, enc_pa_j, key1)
    else:
        if compare(enc_q_j, enc_pa_j, key1) == -1 and compare(enc_pb_j, enc_q_j, key1) == -1:
            return compare(enc_pa_pb_j, enc_2q_j, key2)
        else:
            return compare(enc_pb_j,enc_q_j, key1)