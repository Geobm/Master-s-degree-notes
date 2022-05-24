
/* #include"usuals.h"  enlace detenido*/

typedef char byte;
typedef short unsigned int word16;
typedef char boolean;
typedef unsigned int word32;      /* duda sobre el size de int */
typedef char *byteptr;   /* un byte */
#define  TRUE 1
#define  FALSE 0 


#define IDEAKEYSIZE 16
#define IDEABLOCKSIZE 8

void initcfb_idea();
void ideacfb();
void close_idea();

void init_idearand();
byte idearand();
void close_idearand();
int GetHashedPassPhrase();
void hashpass();
/*
void initcfb_idea( word16 ivO[4], byte key[16], boolean decryp);
void ideacfb(byteptr buf, int count);
void close_idea(void);

void init_idearand(byte key[16], byte seed[8], word32 tstamp);
byte idearand(void);
void close_idearand(void);
int GetHashedPassPhrase(char *keystring, char *hash, boolean noecho);
void hashpass(char *keystring, int keylen, byte *hash);
*/
