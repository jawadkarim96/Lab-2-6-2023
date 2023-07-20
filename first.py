
import bcrypt
import hashlib
text = 'jawad karim'

#calculating the hash function using the bcrypt algorithm
salt = bcrypt.gensalt()
bcrypt_hash = bcrypt.hashpw(text.encode() , salt)
print('bcrypt Hash:' , bcrypt_hash)

#calculating the hash function using the RIPEMD-160 algorithm
ripemd160_hash = hashlib.new('RIPEMD160' , text.encode()).hexdigest()
print("RIPEMD-160 Hash:" , ripemd160_hash)

#calculating the hash function using the MD-5 algorithm
md5_hash = hashlib.md5(text.encode())
print("MD-5 hash: " , md5_hash.hexdigest())

#calculating the hash function using the SHA256 algorithm
sha256 = hashlib.sha256(text.encode())
print("SHA 256: " , sha256.hexdigest())

#calculating the hash function using the SHA512 algorithm
sha512 = hashlib.sha512(text.encode())
print("SHA512 Hash: " , sha512.hexdigest())

#calculating the hash function using the SHA1 algorithm
sha1 = hashlib.sha1(text.encode())
print("Hash SHA1 : " , sha1.hexdigest())

#calculating the hash function using the SHA3-224 algorithm
sha3 = hashlib.sha3_224(text.encode())
print("Hash SHA3-224 : " , sha3.hexdigest())

#calculating the hash function using the SHA3-512 algorithm
sha3 = hashlib.sha3_512(text.encode())
print("Hash SHA3-512 : " , sha3.hexdigest())

#calculating the hash function using the SHA3-256 algorithm
sha3 = hashlib.sha3_256(text.encode())
print("Hash SHA3-256 : " , sha3.hexdigest())

#calculating the hash function using the SHA3-384 algorithm
sha3 = hashlib.sha3_384(text.encode())
print("Hash SHA3-384 : " , sha3.hexdigest())

#calculating the hash function using the BLAKE-2b algorithm
blake2b = hashlib.blake2b(text.encode())
print("Hash BLAKE2b : " , blake2b.hexdigest())

#calculating the hash function using the BLAKE-2s algorithm
blake2s = hashlib.blake2s(text.encode())
print("Hash BLAKE-2s :" , blake2s.hexdigest())

#task number 5
text2 = "Please repeat the above task taking the whole article of your choice from any newspaper. Personally I like this one."
ripemd160 = hashlib.new('RIPEMD160' , text2.encode())
print("Hash of the article : " , ripemd160.hexdigest())

#task number 6
#last two is changed to observe the avalanche effect
text3 = "Please repeat the above task taking the whole article of your choice from any newspaper. Personally I like this two."
ripemd160 = hashlib.new('RIPEMD160' , text2.encode())
print("Hash of the changed article : " , ripemd160.hexdigest())