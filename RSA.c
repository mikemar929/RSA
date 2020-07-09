//Michael Martinez

#include<stdio.h>
#include<openssl/bn.h>

void printBN(char *msg, BIGNUM *a)
{
char* number_str = BN_bn2dec(a);
printf("%s %s\n", msg, number_str);

OPENSSL_free(number_str);
}

int main ()
{
BN_CTX *ctx = BN_CTX_new();

BIGNUM *p, *q, *d, *e, *n, *m, *phi, *p_minus_one, *q_minus_one;
BIGNUM *s, *c, *c2, *dec_msg, *veri_d, *veri_s;
p = BN_new();
q = BN_new();
p_minus_one = BN_new();
q_minus_one = BN_new();
phi = BN_new();
d = BN_new();
e = BN_new();
n = BN_new();
m = BN_new();
s = BN_new();
c = BN_new();
c2 = BN_new();
dec_msg = BN_new();
veri_d = BN_new();
veri_s = BN_new();

//task 1 deriving the private key
BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");//given in lab
BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");//given
BN_hex2bn(&e, "0D88C3");
BN_sub(p_minus_one, p, BN_value_one());
BN_sub(q_minus_one, q, BN_value_one());
//computing p-1 and q-1 for Euler's phi function
BN_mul(n, p, q, ctx);//n=p*q
BN_mul(phi, p_minus_one, q_minus_one, ctx); //phi(n)=(p-a)(q-1)

BN_mod_inverse(d, e, phi, ctx);//d=e^-1 mod phi(n)

printBN("The derived privte key = ",d);

BN_clear_free(p);
BN_clear_free(q);
BN_clear_free(p_minus_one);
BN_clear_free(q_minus_one);
BN_clear_free(phi);//clear_free for variables that wont't be used again
BN_clear(d);
BN_clear(e);
BN_clear(n);//just clear toleave the point in place


//Task 2: encrypting a message

BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
BN_hex2bn(&e, "010001");
BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
BN_hex2bn(&m, "4120746f702073656372657421");//hex for "A top secret!"
BN_mod_exp(c, m, e, n, ctx);// c=m^e mod n
printBN("A top secret! encrypts to ", c);
BN_mod_exp(veri_d, c, d, n, ctx); //test decryption 
printBN("original:", m );
printBN("test decryption: ", veri_d );

BN_clear_free(veri_d);
BN_clear(m);

//Task 3 decrypting a message
BN_hex2bn(&c2, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");
BN_mod_exp(dec_msg, c2, d, n, ctx);//m=c^d mod n. decryption
printBN("For the provided ciphertext, the decrypted message reads ", dec_msg);
printf("A screenshot will be provided with the lab showing this translated back to ASCII.\n\n");

//Task 4 signing a Message.
BN_hex2bn(&m, "49206F776520796F752024323030302E");//hex for "I owe you $2000.
BN_mod_exp(s, m, d, n, ctx); //signing the message
printBN("My digital signature for \"I owe you $2000\" is  ", s);
BN_clear(s);
BN_clear(m);
BN_hex2bn(&m, "49206F776520796F752024333030302E");//hex for " I owe you $3000."
BN_mod_exp(s, m, d, n, ctx);//signature for the changed message
printBN("The changed message's signature is ", s);

BN_clear(m);
BN_clear(s);
BN_clear(e);
BN_clear(n);

//Task 5 Verifying a signature
BN_hex2bn(&s, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
BN_hex2bn(&e, "010001");
BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");//all given in lab
BN_hex2bn(&m, "4C61756E63682061206D6973736C652E");//hex for "Launch a missle."
BN_mod_exp(veri_s, s, e, n, ctx);//DSA
printBN("The message reads ", m);
printBN("My verifcation gave me ", veri_s);

BN_clear_free(d);
BN_clear_free(e);
BN_clear_free(n);
BN_clear_free(m);
BN_clear_free(c);
BN_clear_free(c2);
BN_clear_free(s);
BN_clear_free(dec_msg);
BN_clear_free(veri_s);

return 0;
}
