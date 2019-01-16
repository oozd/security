import sys
from vulnerable import * 

givenCipherSt = sys.argv[1]
noPadText = sys.argv[2]

givenText = list(noPadText + "\x01")
givenCipher = list(givenCipherSt)

T = list("0000000000000000")

for i in range(0, len(givenText)):
	equalSuccess = -1
	nonEqualSuccess = -1
	for j in range (0, 256): 
		char = chr(j)
		givenCipher[31-i] = char
		for k in range(0, i): #first arrange the old bits of cipher
			givenCipher[31-k] = chr( (i+1) ^ ord(T[15-k]) )
		if( decr("".join(givenCipher) ) == "SUCCESS" ):
			if(char != givenCipherSt[31-i] ):
				nonEqualSuccess = j
			else:
				equalSuccess = j
		if(j == 255):
			if(nonEqualSuccess != -1):
				T[15-i] = chr( (i+1) ^ nonEqualSuccess)
			else:
				T[15-i] = chr( (i+1) ^ equalSuccess)

for i in range(0, len(givenText)):
	givenCipher[31-i] = chr( ord(T[15-i]) ^ ord(givenText[ len(givenText) -1 - i] ) )

with open('ciphertext.txt', 'w') as the_file:
    the_file.write("".join(givenCipher))

