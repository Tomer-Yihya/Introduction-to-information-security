from q2_atm import ATM, ServerResponse
import math


def extract_PIN(encrypted_PIN) -> int:
    """Extracts the original PIN string from an encrypted PIN."""
    # TODO: IMPLEMENT THIS FUNCTION
    at = ATM() #create ATM object
    
    #go through all posiable PIN and find which one bring us the same encryption as we get
    for i in range(0, 10000):
        try_pin = i
        try_enc = at.encrypt_PIN(try_pin) #encrypt the i number
        if try_enc == encrypted_PIN: #if equal then the two encryptions are the 
        #same, return i which his encryption same as input
            return i

    return -1 #error
    #raise NotImplementedError()


def extract_credit_card(encrypted_credit_card) -> int:
    """Extracts a credit card number string from its ciphertext."""
    # TODO: IMPLEMENT THIS FUNCTION
    
    #all possiable credit card number power 3 are smaller than n, so we need third root to get
    #back the real credit card number, we do ceil because sometimes we can get close value but 
    #not the same, because of how the computer save data we lose small amount of data
    return math.ceil(pow(encrypted_credit_card, 1/3))
    
    #raise NotImplementedError()


def forge_signature():
    """Forge a server response that passes verification."""
    # Return a ServerResponse instance.
    # TODO: IMPLEMENT THIS FUNCTION
    
    #1 power everything is 1, so that work, the 
    #ATM check if the second argument power 3 mod self.rsa_card.n is
    #the first argument and if the first argument is 1
    return ServerResponse(1, 1)
    
    #raise NotImplementedError()
    
