import gmpy2
from gmpy2 import mpz, powmod, jacobi, to_binary
import Crypto.Random.random as random
from Crypto.Hash import SHA256
from GM import encrypt_gm, dot_mod, embed_and, decrypt_bit_and
import collections

import random as rand

# Called by supplier 1, who bids number1
# Compare number1 vs number2, without revealing number1
# The result is encrypted with pub_key2, to be decrypted later by supplier 2
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

# Called by supplier 2, w.r.t. the document of gm_eval_honest
# Returns True if myNumber <= otherNumber
#                 (number2 <= number1)    
def compare_leq_honest(eval_res, priv_key):
    one_cnt = 0
    for cipher in eval_res:
        if decrypt_bit_and(cipher, priv_key) == '1':
            one_cnt += 1
        
    assert(one_cnt <= 1)
    return one_cnt == 0  

# Pass a random number r for "repeatable" encryption
def encrypt_bit_gm_coin(bit, n, r):
    assert(r >= 0 and r <= n-1)
        
    if bit == '1' or bit == 1:
        M = 1
    elif bit == '0' or bit == 0:
        M = 0
    else:
        return None
            
    return r * r * powmod(n-1, M, n) % n
    
# Returns the hash value of a nested list structure    
def hash_flat(numList):
    h = SHA256.new()
    
    def hash_flat2(h, obj):
        if isinstance(obj, collections.Iterable):
            for x in obj:
                hash_flat2(h, x)
            # end for
        else:
            h.update(to_binary(mpz(obj)))
        # end if
    # end hash_flat2
    hash_flat2(h, numList)
    return h.hexdigest()
# end hash_flat
     
        
# j is 1 and i is 2...
# Called by supplier 1. 
# Returns a proof to the judge that 
#   Dec(cipher12, pub_key2) = Dec(cipher1, pub_key1), without revealing plaintexts
# However the theory doesn't work    
def proof_eval(cipher1, cipher2, cipher12, number1, \
               pub_key1, pub_key2, sound_param=16):
    assert(len(cipher1) == 32)
    assert(len(cipher2) == 32)
    
    bits_v = "{0:032b}".format(number1)   
    
    coins_delta = [ [ random.randint(0,1) for m in range(sound_param) ] \
                      for l in range(32) ]
                      
    coins_gamma = [ [ mpz(random.randint(0, int(pub_key1-1))) \
                      for m in range(sound_param) ] \
                      for l in range(32) ]
                      
    coins_gamma2 = [ [ mpz(random.randint(0, int(pub_key2-1))) \
                       for m in range(sound_param) ] \
                       for l in range(32) ]
                      
    coins_GAMMA = [ [ mpz(random.randint(0, int(pub_key1-1))) \
                      for m in range(sound_param) ] \
                      for l in range(32) ]
                      
    coins_GAMMA2 = [ [ mpz(random.randint(0, int(pub_key2-1))) \
                       for m in range(sound_param) ] \
                       for l in range(32) ]
                         
    gamma = [ [encrypt_bit_gm_coin(coins_delta[l][m] , \
                                   pub_key1, \
                                   coins_gamma[l][m]) \
               for m in range(sound_param) ] for l in range(32) ]
               
    gamma2 = [ [encrypt_bit_gm_coin(coins_delta[l][m] , \
                                    pub_key2, \
                                    coins_gamma2[l][m]) \
                for m in range(sound_param) ] for l in range(32) ]
               
    GAMMA = [ [encrypt_bit_gm_coin(coins_delta[l][m] ^ int(bits_v[l]), \
                                   pub_key1, \
                                   coins_GAMMA[l][m] ) \
               for m in range(sound_param) ] for l in range(32) ]
               
    GAMMA2 = [ [encrypt_bit_gm_coin(coins_delta[l][m] ^ int(bits_v[l]), \
                                    pub_key2, \
                                    coins_GAMMA2[l][m]) \
               for m in range(sound_param) ] for l in range(32) ]
               
    P_eval = [ gamma, gamma2, GAMMA, GAMMA2, cipher1, cipher2, cipher12 ]
    
    h = hash_flat(P_eval)
    
    # not thread-safe...
    rand.seed(h)
    
    b_coins = [ [ rand.randint(0,1) for m in range(sound_param) ] \
                            for l in range(32) ]
                            
    def gamma_or_GAMMA(l, m, rand_gen=rand):
        if rand_gen.randint(0,1) == 0:
            return (coins_delta[l][m], \
                    coins_gamma[l][m], \
                    coins_gamma2[l][m])
        else:
            return (coins_delta[l][m] ^ int(bits_v[l]), \
                    coins_GAMMA[l][m], \
                    coins_GAMMA2[l][m])
        # end if
    # end                                   
    
    plaintext_and_coins = [ [ gamma_or_GAMMA(l, m) \
                              for m in range(sound_param) ] \
                              for l in range(32) ]
                                                               
    return P_eval, plaintext_and_coins                  
# end proof_eval                      

# Called by the judge 
# Supposed to return res if pass, or None on failure
# However just returns the encrypted comarison reslt...
def verify_eval(P_eval, plaintext_and_coins, \
                n1, n2, sound_param=16):
    if len(P_eval) != 7:
        return None
                              
    gamma, gamma2, GAMMA, GAMMA2, cipher1, cipher2, cipher12 = P_eval
    
    # use assert for now..
    for x in P_eval:
        assert(len(x) == 32)
        
    # Doesn't work... 
    # Just do the comparison
    """
    # verify homomorphic relations
    for l in range(32):
        assert(len(gamma[l]) == sound_param)
        assert(len(GAMMA[l]) == sound_param)
        assert(len(gamma2[l]) == sound_param)
        assert(len(GAMMA2[l]) == sound_param)
        
        for m in range(sound_param):
            if gamma[l][m] * cipher1[l] % n1 != GAMMA[l][m]:
                return None
            if gamma2[l][m] * cipher12[l] % n2 != GAMMA2[l][m]:
                print "homo 2 fail"
                return None
        # end for
    # end for
    
    h = hash_flat(P_eval)
    # not thread-safe...
    rand.seed(h)
    
    # verify encryption
    for l in range(32):
        assert(len(plaintext_and_coins[l]) == sound_param)
        for m in range(sound_param):
            plaintext, coins_gamma, coins_gamma2 = \
            plaintext_and_coins[l][m]
            
            if rand.randint(0, 1) == 0:
                # gamma, gamma2
                if encrypt_bit_gm_coin(plaintext, n1, coins_gamma) != gamma[l][m]:
                    print "enc gamma fail"
                    return None
                elif encrypt_bit_gm_coin(plaintext, n2, coins_gamma2) != gamma2[l][m]:
                    print "enc gamma2 fail"
                    return None
            else:
                # GAMMA, GAMMA2
                if encrypt_bit_gm_coin(plaintext, n1, coins_gamma) != GAMMA[l][m]:
                    print "enc GAMMA fail"
                    return None
                elif encrypt_bit_gm_coin(plaintext, n2, coins_gamma) != GAMMA2[l][m]:
                    print "enc GAMMA2 fail"
                    return None
            # end if
        # end for
    # end for
    """
    # compute res            
    neg_cipher1 = map(lambda x: x * (n2-1) % n2, cipher12)
    c_neg_xor = dot_mod(neg_cipher1, cipher2, n2)
    
    cipher1_and = embed_and(cipher12, n2)
    cipher2_and = embed_and(cipher2, n2)
    neg_cipher1_and = embed_and(neg_cipher1, n2)
    c_neg_xor_and = embed_and(c_neg_xor, n2)
    
    res = [ ]
    for l in range(32):
        temp = dot_mod(cipher2_and[l], neg_cipher1_and[l], n2)        
        for u in range(l):
            temp = dot_mod(temp, c_neg_xor_and[u], n2)
        # end for
        res.append(temp)
    # end for
    
    random.shuffle(res)
    return res 
# end verify_eval  


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
     
        
        
   
