import gmpy2
from gmpy2 import mpz, powmod, jacobi, to_binary
import Crypto.Random.random as random
from Crypto.Hash import SHA256
from GM import encrypt_gm, dot_mod, embed_and, decrypt_bit_and

import random as rand

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

# j is 1 and i is 2...    
def proof_eval(cipher1, cipher2, cipher12, res12, number1, \
               pub_key1, pub_key2, sound_param=16):
    assert(len(cipher1) == 32)
    assert(len(cipher2) == 32)
    P_eval = [ cipher12 ]


def get_rand_Jn1(n, rand_gen=random):
    r = rand_gen.randint(0, int(n-1))
    while jacobi(r, n) != 1:
        r = rand_gen.randint(0, int(n-1))
    return r 
    
def set_rand_seed(numList):
    h = SHA256.new()
    
    for x in numList:
        h.update(to_binary(mpz(x)))
    
    # not thread-safe!
    # Not using Crypto.random because:
    #   1. Need to set seed;
    #   2. It's predictable anyway...
    rand.seed(h.hexdigest())
    
def proof_dlog_eq(sigma, y, n, iters=10):
    P_dlog = []
    z = n - 1
    
    Y = powmod(y, sigma, n)
    Z = powmod(z, sigma, n)
    
    for i in range(iters):
        r = get_rand_Jn1(n)
        
        t1 = powmod(y, r, n)
        t2 = powmod(z, r, n)
        
        set_rand_seed([y, z, Y, Z, t1, t2, i])
        
        c = get_rand_Jn1(n, rand_gen=rand)
        s = r + c * sigma
        
        P_dlog.append([t1, t2, s])
        
    return P_dlog
    
def verify_dlog_eq(n, y, Y, Z, P_dlog, K=10):
    if len(P_dlog) < K:
        return False
        
    z = n - 1
    
    for i in range(K):
        proof = P_dlog[i]
        if len(proof) != 3:
            return False
            
        t1 = proof[0]
        t2 = proof[1]
        s = proof[2]
        
        set_rand_seed([y, z, Y, Z, t1, t2, i])
        
        c = get_rand_Jn1(n, rand_gen=rand)        
 
        if powmod(y, s, n) != t1 * powmod(Y, c, n) % n:
            return False
        elif powmod(z, s, n) != t2 * powmod(Z, c, n) % n:
            return False
    # for
    return True            
     
        
        
        
        
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
