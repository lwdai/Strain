import gmpy2
import Crypto.Random.random as random
from gmpy2 import mpz, powmod, isqrt, jacobi, to_binary
from Crypto.Util.number import getStrongPrime



def generate_keys(prime_size = 768):
    p = getStrongPrime(prime_size)
    while mpz(p) % 4 != 3:
        p = getStrongPrime(prime_size)
    
    # Use more bits to prevent factorization    
    q = getStrongPrime(prime_size + 128)
    while mpz(q) % 4 != 3:
        q = getStrongPrime(prime_size + 128)
    
    p = mpz(p)
    q = mpz(q)
    
    n = p * q
     
    keys = {'pub': n, 'priv': (p, q)}
    return keys

   
def encrypt_bit_gm(bit, n):
    r = mpz(random.randint(0, int(n-1)))
        
    if bit == '1' or bit == 1:
        M = 1
    elif bit == '0' or bit == 0:
        M = 0
    else:
        return None
            
    return r * r * powmod(n-1, M, n) % n
        
def encrypt_gm(mpz_number, pub_key):
    bits_str = "{0:032b}".format(mpz_number)
        
    return [encrypt_bit_gm(bit, pub_key) for bit in bits_str]
    
def decrypt_bit_gm(c, sk_gm, n):
    if powmod(c, sk_gm, n) == 1:
        return '0'
    else:
        return '1'
    
def decrypt_gm(cipher_numbers, priv_key):
    p, q = priv_key
    n = p * q
    
    sk_gm = (p-1)*(q-1) / 4
    
    for c in cipher_numbers:
        if c >= n or jacobi(c, n) != 1:
            # rejct
            return None
                    
    bits_str = ''.join([decrypt_bit_gm(c, sk_gm, n) for c in cipher_numbers])
    return int(bits_str, 2)
    
def quad_residue(c, priv_key):
    p, q = priv_key
    n = p * q
    sk_gm = (p-1)*(q-1) / 4
    return jacobi(c, n) and powmod(c, sk_gm, n) == 1
    
def encrypt_bit_and(bit, pub_key, size_factor=128):
    if bit == '1':
        return [ encrypt_bit_gm(0, pub_key) for i in range(size_factor) ]
    else:
        return [ encrypt_bit_gm(random.randint(0,1), pub_key) \
                 for i in range(size_factor) ]
                 
def decrypt_bit_and(cipher, priv_key, size_factor=128):
    for c in cipher:
        if not quad_residue(c, priv_key):
            return '0'
    return '1'

             
def dot_mod(cipher1, cipher2, n):
    return [ c1 * c2 % n for c1,c2 in zip(cipher1, cipher2) ]
 

def encrypt_gm_and(mpz_number, pub_key, size_factor=128):
    bits_str = "{0:032b}".format(mpz_number)
 
def embed_bit_and(bit_cipher, pub_key, size_factor=128):
    def embed(bit_cipher, n):
        if random.randint(0,1) == 1:
            return encrypt_bit_gm(0, n)
        else:
            return encrypt_bit_gm(0, n) * bit_cipher * (n-1) % n
           
    return [ embed(bit_cipher, pub_key) for i in range(size_factor) ]
    
       

def compare_leq(val1, pub_key2, cipher2):
    cipher1 = encrypt_gm(val1, pub_key2)
    
    
    
    
           
#print to_binary(mpz(123))
#print "{0:b}".format(mpz(123))
#print bin(mpz(123))

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
        num = mpz(random.randint(0, 2**31))
        #print "i= ", i, "num = ", num
        cipher = encrypt_gm(num, n)
        
        # ReEncryption
        for j in range(3):
            cipher = [c * encrypt_gm(0, n)[0] % n for c in cipher ]
        
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
        assert(decrypt_bit_and(dot_mod(cipher0, encrypt_bit_and('1', n), n), priv) == '0')
        assert(decrypt_bit_and(dot_mod(cipher0, encrypt_bit_and('0', n), n), priv) == '0') 
        assert(decrypt_bit_and(dot_mod(cipher1, encrypt_bit_and('1', n), n), priv) == '1')    
        
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
    
    #test_gm_enc_dec(iters=10)
    
    #test_gm_homo(iters=10)  
    
    #test_gm_bit_and(iters=10)
    
    test_embed_bit_and(iters=10)
    print "test_gm pass"
    
test_gm()  

            
           
    
    


