import gmpy2
import Crypto.Random.random as random
from gmpy2 import mpz
from GM import generate_keys, encrypt_gm
from proofs import gm_eval_honest, compare_leq_honest

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
    
    
def test_proofs():
    print "test_proofs:"
    test_gm_eval_honest(iters=10)
    print "test_proofs pass"
    
test_proofs()
