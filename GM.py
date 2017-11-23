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
   
    
def encrypt_gm(mpz_number, pub_key):
    bits_str = "{0:b}".format(mpz_number)
    
    def encrypt_bit(bit, n):
        r = random.randint(0, int(n-1))
        
        if bit == '1':
            M = 1
        else:
            M = 0
            
        return r * r * powmod(n-1, M, n) % n
        
    return [encrypt_bit(bit, pub_key) for bit in bits_str]
    
def decrypt_gm(cipher_numbers, priv_key):
    p, q = priv_key
    n = p * q
    
    sk_gm = (p-1)*(q-1) / 4
    
    for c in cipher_numbers:
        if c >= n or jacobi(c, n) != 1:
            # rejct
            return None
   
    def decrypt_bit(c, sk_gm, n):
        if powmod(c, sk_gm, n) == 1:
            return '0'
        else:
            return '1'
                    
    bits_str = ''.join([decrypt_bit(c, sk_gm, n) for c in cipher_numbers])
    return int(bits_str, 2)
    
    
    
#print to_binary(mpz(123))
#print "{0:b}".format(mpz(123))
#print bin(mpz(123))

def test_gen_keys(iters = 1):
    
    for i in range(iters):
        print "i= ", i
        keys = generate_keys()
            
        n = keys['pub']
        p, q = keys['priv']
            
        assert(jacobi(n-1, n) == 1)
    print "test_gen_keys pass"

def test_gm_enc_dec(iters = 1):
    keys = generate_keys()
    
    n = keys['pub']
    p, q = keys['priv']
    
    print n, p, q
    
    for i in range(iters):       
        num = mpz(random.randint(0, 2**31))
        print "i= ", i, "num = ", num
        cipher = encrypt_gm(num, n)
        
        # ReEncryption
        for j in range(3):
            cipher = [c * encrypt_gm(0, n)[0] % n for c in cipher ]
        
        decrypted = decrypt_gm(cipher, (p,q))
        
        assert(decrypted != None)
        assert(decrypted == num)
        
    print "test_gm_enc_dec pass"
        
 
def test_gm_homo(iters = 1):

    for i in range(iters):
        print "i = ", i
        keys = generate_keys()
        
        n = keys['pub']
        p, q = keys['priv']
        
        c0 = encrypt_gm(mpz(0), n)[0]
        c1 = encrypt_gm(mpz(1), n)[0]
        #print c0, c1
       
        # XOR
        assert(decrypt_gm([c0 * c1 % n], keys['priv']) == 1)
        assert(decrypt_gm([c0 * c0 % n], keys['priv']) == 0)
        assert(decrypt_gm([c1 * c1 % n], keys['priv']) == 0)
        
        # flip
        assert(decrypt_gm([c0 * (n-1) % n], keys['priv']) == 1)
        assert(decrypt_gm([c1 * (n-1) % n], keys['priv']) == 0)
        
        
    print "test_gm_homo pass"
                
        
def test_gm():
    print "test_gen_keys:"
    test_gen_keys(iters=10)
    print "test_gm_enc_dec:"
    test_gm_enc_dec(iters=10)
    print "test_gm_homo:"
    test_gm_homo(iters=10)  
    print "test_gm"
    
test_gm()  
            
           
    
    


