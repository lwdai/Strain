import gmpy2
import Crypto.Random.random as random
from gmpy2 import mpz,jacobi
from Crypto.Util.number import getStrongPrime
from GM import generate_keys, encrypt_bit_gm, encrypt_gm, decrypt_bit_gm,\
    decrypt_gm, encrypt_bit_and, decrypt_bit_and, dot_mod, \
    embed_bit_and, embed_and
    
def test_gen_keys(iters = 1):
    print "test_gen_keys:"
    for i in range(iters):
        print "i= ", i
        keys = generate_keys()
            
        n = keys['pub']
        p, q = keys['priv']
            
        assert(jacobi(n-1, n) == 1)
    print "test_gen_keys pass"

def test_gm_enc_dec(iters = 1):
    print "test_gm_enc_dec:"
    
    keys = generate_keys()
    
    n = keys['pub']
    p, q = keys['priv']
    
    #print n, p, q
    
    for i in range(iters):       
        num = mpz(random.randint(0, 2**31-1))
        #print "i= ", i, "num = ", num
        cipher = encrypt_gm(num, n)
        
        # ReEncryption
        #for j in range(3):
        #    cipher = [c * encrypt_gm(0, n)[0] % n for c in cipher ]
        
        decrypted = decrypt_gm(cipher, (p,q))
        
        assert(decrypted != None)
        assert(decrypted == num)
        
    print "test_gm_enc_dec pass"
        
 
def test_gm_homo(iters = 1):
    print "test_gm_homo:"
    for i in range(iters):
        #print "i = ", i
        keys = generate_keys()
        
        n = keys['pub']
        p, q = keys['priv']
        
        c0 = encrypt_bit_gm(0, n)
        c1 = encrypt_bit_gm(1, n)
        #print c0, c1
       
        # XOR
        assert(decrypt_gm([c0 * c1 % n], keys['priv']) == 1)
        assert(decrypt_gm([c0 * c0 % n], keys['priv']) == 0)
        assert(decrypt_gm([c1 * c1 % n], keys['priv']) == 0)
        assert(c0 * c1 % n == encrypt_bit_gm(1, n) )
        
        # flip
        assert(decrypt_gm([c0 * (n-1) % n], keys['priv']) == 1)
        assert(decrypt_gm([c1 * (n-1) % n], keys['priv']) == 0)
        
        
    print "test_gm_homo pass"

def test_gm_bit_and(iters = 1):
    print "test_gm_bit_and"
    keys = generate_keys()
    
    n = keys['pub']
    priv = keys['priv']
    
    for i in range(iters):
        #print "i=", i
        cipher0 = encrypt_bit_and('0', n)
        cipher1 = encrypt_bit_and('1', n)
        
        bit0 = decrypt_bit_and(cipher0, priv)
        bit1 = decrypt_bit_and(cipher1, priv)
        
        assert(bit0 == '0')
        assert(bit1 == '1')
        
        # AND
        # Doesn't work if two ciphertexts are the same.
        #assert(decrypt_bit_and(dot_mod(cipher0, encrypt_bit_and('1', n), n), priv) == '0')
        #assert(decrypt_bit_and(dot_mod(cipher0, encrypt_bit_and('0', n), n), priv) == '0') 
        #assert(decrypt_bit_and(dot_mod(cipher1, encrypt_bit_and('1', n), n), priv) == '1')
            
        
    print "test_gm_bit_and pass"                  

def test_embed_bit_and(iters=1):
    print "test_embed_bit_and"
    keys = generate_keys()    
    n = keys['pub']
    priv_key = keys['priv']

    for i in range(iters):
        bit = random.randint(0,1)
        cipher = encrypt_bit_gm(bit, n)
        
        cipher_and = embed_bit_and(cipher, n)
        assert(decrypt_bit_and(cipher_and, priv_key) == str(bit))
        
    print "test_embed_bit_and pass"
        
      
           
def test_gm():
    print "test_gm"
    
    #test_gen_keys(iters=10)
    
    #test_gm_enc_dec(iters=100)
    
    #test_gm_homo(iters=10)  
    
    test_gm_bit_and(iters=100)
    
    #test_embed_bit_and(iters=10)
    
    print "test_gm pass"
    
test_gm() 
