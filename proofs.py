import Crypto.Random.random as random
from GM import encrypt_gm, dot_mod, embed_and, decrypt_bit_and


def gm_eval_honest(number1, cipher2, pub_key2):
    assert(len(cipher2) == 32)
    n = pub_key2
    cipher1 = encrypt_gm(number1, n)
    
    neg_cipher1 = map(lambda x: x * (n-1) % n, cipher1)
    c_neg_xor = dot_mod(neg_cipher1, cipher2, n)
    
    cipher1_and = embed_and(cipher1, pub_key2)
    cipher2_and = embed_and(cipher2, pub_key2)
    neg_cipher1_and = embed_and(neg_cipher1, pub_key2)
    c_neg_xor_and = embed_and(c_neg_xor, pub_key2)
    
    res = [ ]
    for l in range(32):
        temp = dot_mod(cipher2_and[l], neg_cipher1_and[l], n)        
        for u in range(l):
            temp = dot_mod(temp, c_neg_xor_and[u], n)
        res.append(temp)
    
    random.shuffle(res)
    return res

# Returns True if myNumber <= otherNumber     
def compare_leq_honest(eval_res, priv_key):
    one_cnt = 0
    for cipher in eval_res:
        if decrypt_bit_and(cipher, priv_key) == '1':
            one_cnt += 1
        
    assert(one_cnt <= 1)
    return one_cnt == 0  
