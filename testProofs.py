import gmpy2
import Crypto.Random.random as random
from gmpy2 import mpz, powmod
from GM import generate_keys, encrypt_gm
from proofs import gm_eval_honest, compare_leq_honest, proof_dlog_eq, \
    verify_dlog_eq

def test_gm_eval_honest(iters=1):
    print "test_gm_eval_honest"
    keys = generate_keys()    
    n = keys['pub']
    priv_key = keys['priv']  
    
    for i in range(iters):
        
        v1 = mpz(random.randint(0, 2**31-1))
        v2 = mpz(random.randint(0, 2**31-1))
        print 'i=',i,'v1=', v1, 'v2=',v2
        cipher2 = encrypt_gm(v2, n)
        
        eval_res = gm_eval_honest(v1, cipher2, n)
        
        assert( (v2 <= v1) == compare_leq_honest(eval_res, priv_key) )
        
    print "test_gm_eval_honest pass"

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
    #test_gm_eval_honest(iters=10)
    test_dlog_eq(iters=100)
    print "test_proofs pass"
    
test_proofs()

