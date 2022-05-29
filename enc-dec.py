from Crypto.Cipher import DES
import hashlib
import base64
import secrets

session="5MgMB6Oo5OPMO3JblA7PFZHX7hY3Mzgn9408ycTJzFYCmEsXq1L2qA=="

print(session)

def des_decrypt(value):
    password = "qwerty123"
    salt = '\x28\xAB\xBC\xCD\xDE\xEF\x00\x33'
    key = password + salt
    m = hashlib.md5(key.encode('utf-8'))
    key = m.digest()
    (dk, iv) = (key[:8], key[8:])
    crypter = DES.new(dk, DES.MODE_CBC, iv)  
    ciphertext = base64.b64decode(value)
    plaintext = crypter.decrypt(ciphertext)
    return plaintext
    
     
decryptedvalue = (des_decrypt(session))
    
print(decryptedvalue)

def des_encrypt(value):
    password = "qwerty123"
    salt = '\x28\xAB\xBC\xCD\xDE\xEF\x00\x33'
    key = password + salt
    m = hashlib.md5(key.encode('utf-8'))
    key = m.digest()
    (dk, iv) = (key[:8], key[8:])
    crypter = DES.new(dk, DES.MODE_CBC, iv)
    ciphertext = crypter.encrypt(value.encode('ascii'))
    return base64.b64encode(ciphertext).decode('ascii')    



encryptedvalue = (des_encrypt(decryptedvalue.decode("utf-8") ))
    
print(encryptedvalue)