import gmpy2
import Crypto.Random.random as random
from gmpy2 import mpz, powmod, isqrt, jacobi, to_binary
from Crypto.Util.number import getStrongPrime

AND_SIZE_FACTOR = 128

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
    
def encrypt_bit_and(bit, pub_key, size_factor=AND_SIZE_FACTOR):
    if bit == '1':
        return [ encrypt_bit_gm(0, pub_key) for i in range(size_factor) ]
    else:
        return [ encrypt_bit_gm(random.randint(0,1), pub_key) \
                 for i in range(size_factor) ]
                 
def decrypt_bit_and(cipher, priv_key, size_factor=AND_SIZE_FACTOR):
    for c in cipher:
        if not quad_residue(c, priv_key):
            return '0'
    return '1'

             
def dot_mod(cipher1, cipher2, n):
    return [ c1 * c2 % n for c1,c2 in zip(cipher1, cipher2) ]
 
def embed_bit_and(bit_cipher, pub_key, size_factor=AND_SIZE_FACTOR):
    def embed(bit_cipher, n):
        if random.randint(0,1) == 1:
            return encrypt_bit_gm(0, n)
        else:
            return encrypt_bit_gm(0, n) * bit_cipher * (n-1) % n
           
    return [ embed(bit_cipher, pub_key) for i in range(size_factor) ]
    

def embed_and(cipher, pub_key, size_factor=AND_SIZE_FACTOR):
    return [ embed_bit_and(bit_cipher, pub_key, size_factor) \
             for bit_cipher in cipher ]    
               
   
        
        
    
    
    
    
           
#print to_binary(mpz(123))
#print "{0:b}".format(mpz(123))
#print bin(mpz(123))

 

            
           
    
    


