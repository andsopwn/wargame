import ContinuedFractions, Arithmetic, RSAvulnerableKeyGenerator

def hack_RSA(e,n):
    '''
    Finds d knowing (e,n)
    applying the Wiener continued fraction attack
    '''
    frac = ContinuedFractions.rational_to_contfrac(e, n)
    convergents = ContinuedFractions.convergents_from_contfrac(frac)
    
    for (k,d) in convergents:
        
        #check if d is actually the key
        if k!=0 and (e*d-1)%k == 0:
            phi = (e*d-1)//k
            s = n - phi + 1
            # check if the equation x^2 - s*x + n = 0
            # has integer roots
            discr = s*s - 4*n
            if(discr>=0):
                t = Arithmetic.is_perfect_square(discr)
                if t!=-1 and (s+t)%2==0:
                    print("Hacked!")
                    return d
# RSAwienerHacker.py
if __name__ == "__main__":
    n = 116306147098438018096389009087942318199691950855197659865996258007734406069224365157987069636297989747248730584368651405951387774057971474686604671904787015886694401183535004438305874424565983922127346697432188320870268265743577655008680432983095256023649185143898924479396106253951695525422840232620932557317
    e = 65537
    c = 20128920311285571200557056107619946729113993706931501979639889896874725747330363071766401103469647150951580720515487922094658799500566279106466095775066123186140718829238506823320434354136203783628781516876676305950089891518123714379561770006234878267698905970680480714553640351712079378631576932142613618852
    d = hack_RSA(e, n)
    print(d)
