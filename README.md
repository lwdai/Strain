# Strain

# Environment:
Ubuntu 16.04 LTS  
Python 2.7.12  
pycrypto 2.6.1  
gmpy2 2.0.7  

# Runnable files:
$ python testGM.py  
$ python testProofs.py  
$ python auction.py  

Comment or uncomment tests in the files above, as needed.

# Benchmark:

The runtime of the auction is O(s^2) where s is the number of suppliers.  
With 5 suppliers, the auction takes about 4 minutes.

# Pitfalls:
proof_eval and verify_eval are executed, but they don't actually work against malicious adversaries.
