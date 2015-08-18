'''
#########################################################
2-PARTY RSA WITH A TRUSTED DEALER IN THE MALICIOS SETTING
#########################################################

This programm is an example implementation of RSA decryption with two parties.
The protocol assumes a trusted dealer, that is, given a private key a trusted
entity computes secret shares for both parties based on a given private key. 

The setup phase will typecast the given values to internal ones.
The initialization phase is performed by the dealer. Shares will be randomly
generated (please provide a system that provides cryptographically secure
random numbers), the private key CAN be deleted afterwards.
The distributive decryption uses RSA's homomorphic attributes to perform
decryption on the shares on both parties separately. No one learns information
about the share of the other party or the private key.
In this case, only the first entity is interested in the decryption, the second one
serves as a second factor to prevent private key compromise. The second entity
sends it's result to the first one. The first one can retrive the message by
multiplying the ciphertexts.
Afterwards, the first party has to check the message padding. Its length, tag
and separator according to RFC 2313 are verified. In case of success, the
message is unpadded and returned in its hex representation.
'''

'''
This is a private key, generated and printed
by openssl

Private-Key: (512 bit)
modulus:
    00:b6:65:b6:57:37:a4:3e:93:8c:84:09:75:01:ae:
    fd:f1:ff:31:74:17:5e:86:f5:8c:7e:6f:da:b1:76:
    19:0f:ff:e0:64:03:98:32:44:53:44:58:bf:84:a2:
    f5:36:d3:41:7f:99:2a:58:b0:55:be:56:52:06:5b:
    4c:74:ac:1b:c9
publicExponent: 65537 (0x10001)
privateExponent:
    27:fc:2e:37:fa:83:b0:10:2a:8a:bb:84:02:05:79:
    b8:36:68:81:f9:a9:88:4e:86:29:25:9e:3c:af:16:
    19:72:70:e0:72:9a:cb:f5:9c:15:15:61:3a:60:4a:
    b2:43:f3:d1:35:a8:9f:e7:f2:92:00:97:50:14:b4:
    7f:d8:e0:bd
prime1:
    00:da:1c:30:90:ae:66:6d:24:e7:50:06:50:7c:c7:
    1f:4f:9e:dc:a3:6a:76:46:2d:7f:31:60:31:4c:c9:
    7b:1c:fb
prime2:
    00:d6:15:4c:cc:22:28:fc:5d:ac:df:73:bf:17:67:
    70:fb:24:02:d3:0f:37:77:f7:46:d3:a9:23:b2:ca:
    15:07:0b
exponent1:
    00:b2:fc:51:2a:59:c3:fa:2b:3f:9b:5f:23:2b:d2:
    68:32:79:a6:8c:80:30:41:14:d2:fd:1c:f8:38:10:
    5b:74:83
exponent2:
    1f:7d:72:96:74:4f:e3:0f:44:66:79:f8:19:d1:35:
    65:3b:9e:ce:bc:e6:43:d7:33:ab:de:ad:49:97:40:
    10:91
coefficient:
    00:90:96:e3:4b:76:09:3a:fe:b1:fc:88:7b:4d:e7:
    89:ca:26:14:cd:af:8a:99:58:8e:9b:db:14:a9:04:
    09:1e:af
'''

import sys

###########
#setup phase
###########

#from the above example keys, the private key and modulus is extraced and put into a string
d_str = "27:fc:2e:37:fa:83:b0:10:2a:8a:bb:84:02:05:79:b8:36:68:81:f9:a9:88:4e:86:29:25:9e:3c:af:16:19:72:70:e0:72:9a:cb:f5:9c:15:15:61:3a:60:4a:b2:43:f3:d1:35:a8:9f:e7:f2:92:00:97:50:14:b4:7f:d8:e0:bd"
n_str = "00:b6:65:b6:57:37:a4:3e:93:8c:84:09:75:01:ae:fd:f1:ff:31:74:17:5e:86:f5:8c:7e:6f:da:b1:76:19:0f:ff:e0:64:03:98:32:44:53:44:58:bf:84:a2:f5:36:d3:41:7f:99:2a:58:b0:55:be:56:52:06:5b:4c:74:ac:1b:c9"

#teststring in hex to decrypt
c_str = "0x86D9B95905DAF94936AC8ACF13C4C024EF387A53E2B63F007483C981A5BF5AE13F729AD95B823529A4474006FDD4B6E74CB90AEB96971B6465422E7F3394833D"

#remove colons
line = d_str.replace(":", "")
n_str = n_str.replace(":", "")

#add 0x to tell sage it's a hex string
d_str = '0x' + line
n_str = '0x' + n_str

#create a sage-integer from them
d = Integer(d_str)
n = Integer(n_str)

#in sage, it is sufficient to only apply the modulus on c for further operations. The rest is automatically during the computations
c = Mod(Integer(c_str), n)

print "modulus n =", n
print "private exponent d =", d
print "encrypted message c =", c

####################
#initialization phase
####################

#get a random number in range
set_random_seed()
r_1 = ZZ.random_element(d)
print "r_1 =", r_1

#get the second number derived from it
r_2 = d - r_1
print "r_2 =", r_2

#trusted dealer distributes r_1 and r_2 as intended and deletes d

#######################
#distributive decryption
#######################

#computation of person p_1
m_1 = c^r_1
print "m_1 =", m_1

#computation of person p_2
m_2 = c^r_2
print "m_2 =", m_2

#the one who is not interested in the decryption result sends its result. The other one computes the multiplication
m_recv = m_1 * m_2
#make a hex-string from it
m_recv = Integer(m_recv).str(base=16)
print "m_recv =", m_recv

########################
#padding check
########################
#one of the entities has to check the padding. In this example, only PKCS #7 v1.5 Padding for RSA decryptiion purposes is supported

#verify the length
#length is always |n| - 12 bits = (|n| - 12) / 4 digits
#RSA 512: 125
#RSA 1024: 253
#RSA 2048: 509 digits
#RSA 4096: 1021
if not (len(m_recv) == 125 or len(m_recv) == 253 or len(m_recv) == 509 or len(m_recv) == 1021):
    print "wrong length:", len(m_recv) 
    sys.exit()

#verify its tag is correct
if  m_recv[:1] == '0' or m_recv[:1] == '1':
    print "stop here, looks like padding is base on a private key operation instead of a public key operation"
    sys.exit()
elif m_recv[:1] != '2':
    print "stop here, looks like padding is something else than pkcs#7 v1.5"
    sys.exit()

#complete first nibble which got lost by the mathematical operation
m_recv = '0' + m_recv
#group nibble to hex values by adding spaces in between
m_recv =' '.join(a+b for a,b in zip(m_recv[::2], m_recv[1::2]))
#separate message from padding, separator is '00'
message = m_recv.split('00')[1].replace(' ', '')
if not message:
    print "delimiter '00' couldn't be found. Stop"
    sys.exit()

print "message(hex) =", message
#the original message was a tripple-DES key, therefore the result should be exacly 192 bit long
print "message length in bit:", len(message)*4