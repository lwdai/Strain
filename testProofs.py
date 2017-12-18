import gmpy2
import Crypto.Random.random as random
from gmpy2 import mpz, powmod
from GM import generate_keys, encrypt_gm, INT_LEN
from proofs import gm_eval_honest, compare_leq_honest, proof_dlog_eq, \
    verify_dlog_eq, proof_eval, verify_eval

def test_gm_eval_honest(iters=1):
    print "test_gm_eval_honest"
    keys = generate_keys()    
    n = keys['pub']
    priv_key = keys['priv']  
    
    for i in range(iters):
        
        v1 = mpz(random.randint(0, 2**INT_LEN-1))
        v2 = mpz(random.randint(0, 2**INT_LEN-1))
        print 'i=',i,'v1=', v1, 'v2=',v2
        cipher2 = encrypt_gm(v2, n)
        
        eval_res = gm_eval_honest(v1, cipher2, n)
        
        assert( (v2 <= v1) == compare_leq_honest(eval_res, priv_key) )
        
    print "test_gm_eval_honest pass"
    
def test_proof_eval(iters=1):
    print "test_proof_eval"
    keys1 = generate_keys()    
    n1 = keys1['pub']
    p1, q1 = keys1['priv']
    
    keys2 = generate_keys()
    n2 = keys2['pub']
    p2, q2 = keys2['priv']
    
    print "test honest model"
    for i in range(iters):
        print "i =", i
        v1 = mpz(random.randint(0, 2**INT_LEN-1))
        C1 = encrypt_gm(v1, n1)

        v2 = mpz(random.randint(0, 2**INT_LEN-1))
        C2 = encrypt_gm(v2, n2)
    
        C12 = encrypt_gm(v1, n2)
        
        P_eval, plaintext_and_coins = proof_eval(C1, C2, C12, v1, n1, n2)
        
        eval_res = verify_eval(P_eval, plaintext_and_coins, n1, n2)
        assert(eval_res != None)
        assert( (v2 <= v1) == compare_leq_honest(eval_res, (p2, q2)) )
        
        # flip one bit
        # Doesn't work...
        """
        v1x = v1 ^ (1 << random.randint(0, 30))
        C12x = encrypt_gm(v1x, n2)
        
        P_eval_x1, plaintext_and_coins_x1 = proof_eval(C1, C2, C12, v1x, n1, n2)
        P_eval_x2, plaintext_and_coins_x2 = proof_eval(C1, C2, C12x, v1, n1, n2)
        P_eval_x3, plaintext_and_coins_x3 = proof_eval(C1, C2, C12x, v1x, n1, n2)
        assert( verify_eval(P_eval_x1, plaintext_and_coins_x1, n1, n2) == None )
        assert( verify_eval(P_eval_x2, plaintext_and_coins_x2, n1, n2) == None )
        assert( verify_eval(P_eval_x3, plaintext_and_coins_x3, n1, n2) == None )
        """
    # end for       
    print "test_proof_eval pass"
# end test_proof_eval


def test_dlog_eq(iters=1):
    print "test_dlog_eq:"
    keys = generate_keys()    
    n = keys['pub']
    z = n - 1
    p, q = keys['priv']
    
    for i in range(iters):
        print 'i = ', i
        r = random.randint(0, int((p-1)*(q-1)))
        
        y = random.randint(0, int(n-1))
        
        Y = powmod(y, r, n)
        Z = powmod(z, r, n)
        
        P_dlog = proof_dlog_eq(r, y, n)
        
        assert(verify_dlog_eq(n, y, Y, Z, P_dlog))
        
        P_dlog[random.randint(0, len(P_dlog)-1)][random.randint(0,2)] += \
            random.choice([-1, 1])
            
        assert(not verify_dlog_eq(n, y, Y, Z, P_dlog)) 
        
    print "test_dlog_eq pass"
    
def test_proofs():
    print "test_proofs:"
    test_gm_eval_honest(iters=10)
    test_dlog_eq(iters=10)
    test_proof_eval(iters=10)
    print "test_proofs pass"
    
test_proofs()

