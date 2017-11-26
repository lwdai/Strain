import gmpy2
import Crypto.Random.random as random
from gmpy2 import mpz, powmod
from GM import generate_keys, encrypt_gm, decrypt_gm
from proofs import proof_dlog_eq, verify_dlog_eq

class MockBlockchain(object):
    def __init__(self, total_suppliers):
        self.S = total_suppliers
        self.pubkeys = [ 0 for i in range(self.S) ]
        
        # keyshares[i][j] = Supplier i is holding the key share of supplier j
        self.keyshares = [ [ 0 for j in range(self.S) ] for i in range(self.S) ]
       
        # cheating[i][j] is True means supplier i thinks j is cheating 
        # cheating[S] is prepared for the judge
        self.cheating = [ [ False for j in range(self.S) ] for i in range(self.S + 1) ]
        
        # random commits submitted; who knows why this is needed...
        self.commits = [ [ 0 for j in range(self.S) ] for i in range(self.S) ]
        
        # P_DLOG[i][j] is the proof submitted by supplier j for the shares of
        #  supplier i
        self.P_DLOG = [ [ None for j in range(self.S) ] for i in range(self.S) ]
        
        self.p_dlog_len = 10
    # end __init__
    
    def check_sid(self, sid):
        assert(sid >= 0 and sid < self.S)
            
    def add_pubkey(self, sid, n):
        self.check_sid(sid)
        self.pubkeys[sid] = n
        
    def get_pubkey(self, sid):
        self.check_sid(sid)
        return self.pubkeys[sid]
        
    def upload_keyshare(self, from_sid, to_sid, secret):
        self.check_sid(from_sid)
        self.check_sid(to_sid)        
        self.keyshares[to_sid][from_sid] = secret
        
    def get_keyshare(self, m_sid, target_sid):
        self.check_sid(m_sid)
        self.check_sid(target_sid)
        return self.keyshares[m_sid][target_sid]
        
    def commit(self, m_sid, target_sid, rho):
        self.check_sid(m_sid)
        self.check_sid(target_sid)
        self.commits[target_sid][m_sid] = rho
        
    def get_commits_sum(self, sid):
        self.check_sid(sid)
        # the "x"
        return sum(self.commits[sid])
        
    def publish_P_DLOG(self, from_sid, to_sid, Y, Z, p_dlog):
        assert(len(p_dlog) >= self.p_dlog_len)
        
        self.P_DLOG[to_sid][from_sid] = (Y, Z, p_dlog)
        
    def get_P_DLOG(self, sid):
        self.check_sid(sid)
        return self.P_DLOG[sid]
        
    def report_cheat(self, from_sid, to_sid):
        assert(from_sid >= 0 and from_sid <= self.S)
        self.check_sid(to_sid)
        print "report_cheat", from_sid, to_sid
        self.cheating[from_sid][to_sid] = True
                
# end MockBlockChain


class Supplier(object):
    def __init__(self, sid, total_suppliers, blockchain):
        self.sid = sid
        self.S = total_suppliers
        assert(sid in range(total_suppliers))
        self.blockchain = blockchain
        
        keys = generate_keys()
        self.n = keys['pub']
        (self.p, self.q) = keys['priv']
        self.gm_sk = (self.p-1)*(self.q-1)
        
    def upload_pubkey(self):
        self.blockchain.add_pubkey(self.sid, self.n)
        
    def upload_share(self, share, to_sid):
        n_i = self.blockchain.get_pubkey(to_sid)
        
        secret = encrypt_gm(share, n_i)
        self.blockchain.upload_keyshare(self.sid, to_sid, secret)
        
    def distribute_key(self, cheat = False):
        # TODO: implement Shamir's secret share...
        total = 0
        
        cheated = False
        for i in range(self.S):
            if i != self.sid:
                if (self.sid != self.S - 1 and i < self.S - 1) or \
                   (self.sid == self.S - 1 and i < self.S - 2):
                    share = random.randint(1, int(self.gm_sk))
                    total = (total + share) % self.gm_sk
                else:
                    share = (self.gm_sk / 4 - total) % self.gm_sk
                
                if cheat and not cheated:
                    share = random.randint(0, int(self.gm_sk)) 
                
                #print "gm_sk/4 = ", self.gm_sk / 4
                #print "share = ", share 
                #print       
                self.upload_share(share, i)
            # end if
        # end for              
    # end distribute_key
    
    def submit_rand_commits(self):
        for i in range(self.S):
            if i == self.sid:
                continue
            n_i = self.blockchain.get_pubkey(i)
            self.blockchain.commit(self.sid, i, mpz(random.randint(1, int(n_i - 1))))
        # for
              
    def prepare_verify_share(self, sid):
        assert(sid != self.sid)
        secret = self.blockchain.get_keyshare(self.sid, sid)
        r = decrypt_gm(secret, (self.p, self.q))
        
        n = self.blockchain.get_pubkey(sid)
        x = self.blockchain.get_commits_sum(sid) % n
        #print "x = ", x
        y = powmod(x, 2, n)
        z = n - 1 
        
        Y = powmod(y, r, n)
        Z = powmod(z, r, n)
        
        #print r, y, n
        p_dlog = proof_dlog_eq(r, y, n, self.blockchain.p_dlog_len)
        
        self.blockchain.publish_P_DLOG(self.sid, sid, Y, Z, p_dlog)
    # end prepare_verify_share
                
    def verify_share(self, sid):
        assert(sid != self.sid)
        Proofs = self.blockchain.get_P_DLOG(sid)
        assert(len(Proofs) == self.S)
        
        n = self.blockchain.get_pubkey(sid)
        x = self.blockchain.get_commits_sum(sid) % n
        y = powmod(x, 2, n)
        
        b_y = 1
        b_z = 1
        interrupted = False
        
        for i in range(self.S):
            if i == sid:
                continue
             
            proof = Proofs[i]
            
            Y = proof[0]
            Z = proof[1]
            P_dlog = proof[2]
            
            i_not_cheat = verify_dlog_eq(n, y, Y, Z, P_dlog, \
                                         K=self.blockchain.p_dlog_len)
                                        
            if not i_not_cheat:
                self.blockchain.report_cheat(self.sid, i)
                # don't know what to do; let supplier (sid) pass
                interrupted = True
                break    
            else:
                b_y = b_y * Y % n
                b_z = b_z * Z % n
        # end for
        
        if (not interrupted) and (b_y != 1 or b_z != n - 1):
            #print b_y, b_z, n
            self.blockchain.report_cheat(self.sid, sid)
        # end if
    # end verify_share 
                
# end Supplier

def auction_init(total_suppliers = 2):
    print "auction init..."
    blockchain = MockBlockchain(total_suppliers)
    
    suppliers = [ Supplier(i, total_suppliers, blockchain) \
                  for i in range(total_suppliers) ]
    
    for s in suppliers:
        s.upload_pubkey()
                    
    return blockchain, suppliers
# auction_init

def distribute_and_verify_keys(blockchain, suppliers, cheaters):
    print "distributing keys..."
    for s in suppliers:
        s.distribute_key( cheat = (s.sid in cheaters) )
    # end for
    
    print "submitting commits..."
    for s in suppliers:
        s.submit_rand_commits()
    
    #print blockchain.commits
    print "preparing to verify key shares..."    
    for i in range(len(suppliers)):
        for j in range(len(suppliers)):
            if i != j:
                suppliers[i].prepare_verify_share(j)
            # end if
        # end for
    # end for
    
    print "verifing key shares..."            
    for i in range(len(suppliers)):
        for j in range(len(suppliers)):
            if i != j:
                suppliers[i].verify_share(j)
            # end if
        # end for
    # end for
    print "key distribution and verification done."
# end distribute_and_verify_keys                  
          
def test_key_distribution(cheaters, num_suppliers=2):
    print "test_key_distribution, cheaters = ", cheaters, " num_suppliers = ",\
          num_suppliers
          
    blockchain, suppliers = auction_init(total_suppliers = num_suppliers)
    
    distribute_and_verify_keys(blockchain, suppliers, cheaters)
    
    #print blockchain.cheating
    
    for i in range(num_suppliers):
        for j in range(num_suppliers):
            if i != j:
                assert(blockchain.cheating[i][j] == (j in cheaters))
        # for
    # for
    
    print "test_key_distribution pass"
    print
# end test_auction


def test_auction():
    #test_key_distribution([])
    #test_key_distribution([0])
    #test_key_distribution([1])
    #test_key_distribution([0,1])
    
    #test_key_distribution([], num_suppliers=3)
    #test_key_distribution([0], num_suppliers=3) 
    #test_key_distribution([0,2], num_suppliers=3)
    #test_key_distribution([0,1,2], num_suppliers=3)
    
    test_key_distribution([0,3], num_suppliers=5)           
test_auction()   
    
    
    
    
                
