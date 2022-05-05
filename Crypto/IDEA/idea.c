#include "idea.h"    	/* define todos los tipos de variables*/
#include <stdio.h>
#include <fcntl.h>

#define ROUNDS		8        	/* No se cambia el valor ,debe ser 8*/
#define KEYLEN		(6*ROUNDS+4)    /* Largo de llave de idea*/

typedef word16 	IDEAkey[KEYLEN];

#ifdef IDEA32
#define low16(x)  ((x) & 0xFFFF)
typedef unsigned int uint16;     /* por lo menos 16 bits, o mas */
#else
#define low16(x) (x) 		/* Se aplica para dejar limitado x a 16 bits */
typedef word16 uint16;          /* a lo mas, 16 bits */
#endif

#ifdef _GNUC_
/* dos lineas de comentarios */
#define CONST _const_
#else
#define CONST
#endif

uint16 flag = 0;


/*Declaracion de funciones para el algoritmo idea*/

static void en_key_idea();
static void de_key_idea();
static void cipher_idea();



/*
	Encuentra el inverso de x, pero no en forma decimal (1/x) sino que
	lo hace de manera binaria, i.e que encuentra un numero que al aplicar la	operacion multiplicacion en n*(x^1) regrese el mismo bloque de bits             llamado x.
*/

CONST static uint16 inv(x)
uint16 x;
{
	uint16 t0,t1;
	uint16 q, y;

   	if (x<=1) return x;  /* Si x es 0 o 1 */
   	t1=0x10001 / x; 
   	y =0x10001 % x;
   	if(y==1) return low16(1-t1);
  	t0 = 1;
   	do{
      	    q=x / y;
      	    x=x % y;
      	    t0 +=q * t1;
      	    if(x == 1) return t0;
      	    q = y / x;
      	    y = y % x;
      	    t1+=q*t0;
   	} while(y != 1);
   	return low16(1-t1);
}   /* fin inf */


/*
	Crea llave de cifrado de 52 enteros, a partir de los 16 caracteres  
	(8 enteros ya traducidos en userkey) insertados como llave en la linea de comando.
*/
static void en_key_idea(userkey, z)
word16 *userkey, *z;
{

	int i,j;
	word16 *t;   // Linea agrgada por GVH

	t=z;         // Linea agrgada por GVH
	for(j=0; j<8; j++){    /* cambio de llave al arreglo llave de cifrado */   
      	    z[j]= *userkey++; 
    	}

   	for (i=0; j<KEYLEN; j++){ /* creacion de los 44 elementos faltantes */	
      	    i++;		  /* a partir de los 8 anteriores	    */
      	    z[i+7] = z[i & 7] << 9 | z[i+1 & 7] >> 7;
      	    z += i & 8;
      	    i &= 7;
    	}

	z=t;        // Linea agrgada por GVH
	flag = 1;
	uint16 t1, t2, t3;
	IDEAkey T;
	word16 *p = T + KEYLEN;
	t1 = inv(*z++);
	t2 = -*z++;
	t3 = -*z++;
	*--p = inv(*z++);
	*--p = t3;
	*--p = t2;
	*--p = t1;
	for (j = 1; j < ROUNDS; j++)
	{
			t1 = *z++;
			*--p = *z++;
			*--p = t1;
			t1 = inv(*z++);
			t2 = -*z++;
			t3 = -*z++;
			*--p = inv(*z++);
			*--p = t2;
			*--p = t3;
			*--p = t1;
	}
	t1 = *z++;
	*--p = *z++;
	*--p = t1;
	t1 = inv(*z++);
	t2 = -*z++;
	t3 = -*z++;
	*--p = inv(*z++);
	*--p = t3;
	*--p = t2;
	*--p = t1;
	for (j = 0, p = T; j < KEYLEN; j++)
	{
			*t++ = *p;
			*p++ = 0;
	}
}     


/*
	Multiplica x,y dejando un resultado maximo de 16 bits ((2^16)-1)
*/

#define MUL(x,y) ((t16 = (y)) ? (x = low16(x)) ? \
	t32 = (word32)x*t16, x = low16(t32),t16 = t32>>16, \
	x = x-t16 +(x<t16) : \
	( x = 1-t16) : (x =1-x) )




/*
	Cifra o decifra el bloque de 4 elementos direccionado a in y lo  
	deposita en el bloque de 4 elementos direccionado a out, dependiendo si 	se utiliza z(llave de cifrado) o si se 	utiliza DK(llave de decifrado).
	en este caso no se incluye el codigo generador de llave para DK ya que  
	este codigo solo cifra. 	
*/

static void cipher_idea(in, out, z)
word16 in[4],out[4];
register CONST IDEAkey z;
{

	 register uint16 x1, x2, x3,x4, t1, t2;
	 register uint16 p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14;

	 register uint16 t16;
	 register word32 t32;

	 int r = ROUNDS;      /* 8 vueltas a lo mas */

	 x1 = *in++; x2 = *in++;
	 x3 = *in++; x4 = *in;
/*
	aplicacion del algoritmo idea que utiliza bloques de la llave(ci-
	framiento o deciframiento) de 6 en 6 para la aplicacion de los pasos
	del 1 al 14,estos paso se repiten hasta cumplir 8 vueltas o 48 elem's
	de la llave,a los cuatro ultimos elementos de la llave se les 
	multiplica o suma con el bloque a cifrado obtenido despues de 8 vueltas. 
*/
	 do{
	     p1=MUL(x1, *z++);
	     p2=x2 + *z++;
	     p3=x3+ *z++;

	     p4=MUL(x4, *z++);
	     p5=p1^p3;
	     p6=p2^p4;

	     p7=MUL(p5, *z++);
	     p8=p6+p7;
	     p9=MUL(p8,*z++);

	     p10=p7+p9;
	     p11=p1^p9;
	     p12=p3^p9;
	     p13=p2^p10;
	     p14=p4^p10;

	     x1=p11;
	     x2=p12;
	     x3=p13;
	     x4=p14;

	 } while(--r);

	 MUL(x1, *z++);
	 *out++ = x1;
	 *out++ =x3 + *z++;
	 *out++ =x2 + *z++;
	 MUL(x4, *z);
	 *out = x4;
}


/*
	copia el nombre del archivo guardado en la direccion s en el arreglo 
   	direccionado a t.
*/
strcpy(s,t)
char *s, *t;
{
	while(*s++ = *t++);
}

/*
	A la copia hecha en strcpy se le adiciona lo que contiene el arreglo 
	de direccion t.
*/

strcnt(s,t)
char *s, *t;
{
	for(;*s!='\0';s++);
	while(*s++ = *t++);
}

#define TAMBUFF 60000	 	 /* Numero de caracteres estimados archivo*/

unsigned char buff1[TAMBUFF+10]; /* arreglo donde se guardan los caracteres
				    del archivo originales. */
unsigned char buff2[TAMBUFF+10]; /* arreglo donde se guardan los caracteres 					    de archivo procesados o cifrados. */

int main(argc, argv)  /* entrada de llave y nombre de archivo a cifrar */ 
int argc;
char *argv[];     /* Guarda ambos datos llave y nombre archivo. */
{
        int m, i, j, k, l, f1, f2, r, b, rb;
        char nomvec[256];
	unsigned char *ent, *sal;
	unsigned char tmp[8];
  	IDEAkey z;		   /* Declaracion llave de ciframiento */
  	word16 userkey[8];					/* (1) */
        unsigned char *llave0 = (unsigned char *) userkey;	/* (2) */

/*
	for que asigna la llave de caracteres del primer argumento en
	llave0 quien directamente manda los valores ha userkey de enteros 
	pormedio de un cast. Expresion (1) y (2). 
*/

        for(i=0;(i<16)&&(argv[1][i]!='\0');i++) llave0[i] = argv[1][i];

  	en_key_idea(userkey,z); /* Llamada ha creacion de llave de ciframiento*/
        strcpy(nomvec,argv[2]); /* Copiar nombre archivo(arvg[2]) en nomvec   */
        strcnt(nomvec,".cif");  /* Agrega a nomvec la extencion .cif	      */
		flag = 0;

         
/*      Abre el archivo de nombre arvg[2] para solo lectura que apunta a f1*/

    	if ((f1= open(argv[2],0)) == -1) {
       	    printf("Error en el archivo %s\n",argv[2]);
	    exit(-1);
	}
/*      crea un nuevo archivo listo para escritura  que apunta a f2*/

        if ((f2 = open(nomvec,O_WRONLY|O_TRUNC|O_CREAT,0644)) == -1) {
            printf("Error al abrir el archivo %s\n",nomvec);
            exit(-1);
        }
/*
	copia los elementos de el archivo al que apunta f1 y los coloca en 
	buff1 mientras existan elementos en el archivo disponibles.
*/
    	while((r=read(f1,buff1,TAMBUFF)) > 0) {
	    b = (r/8);
/*
	 For, que inicia desde 0 hasta b que es el numero de bloques de 8 
	 carecteres disponible para cifrar por el momento. El apuntador
	 ent es un apuntador a buff1 y sal es un apuntador a buff2,de
         tal manera que ent controla las direcciones del archivo fuente    
	 (texto normal) y sal controla las direcciones del archivo destino
	 (cifrado), como cipher_idea requiere de bloques de 4 enteros se hace 
	 un cast a word16 a cada apuntador enviado.
*/
	 
	    for(i=0,ent=buff1,sal=buff2;i<b;i++,ent+=8,sal+=8) 
 		cipher_idea((word16 *) ent,(word16 *) sal,z);

/*
	 Cada que cipher_idea regresa un bloque de 8 caracteres cifrado
	 pormedio de sal que apunta a buff2. Se escribe el contenido de 
	 de buff2 en al archivo destino( que se esta cifrando ).
*/

            if(write(f2,buff2,8*b)!=8*b) {
                printf("Error al escribir en archivo %s\n",nomvec);
                exit(-1);
            }
	    rb = r;
	}
/*
	En caso de que despues de que termine el while sin que todos los
	elementos del archivo fuente se hayan cifrado, por lo tanto se toman
	los archivos restantes y se cifran para inmediatamente incluirlos en
	el nuevo archivoi pormedio del write.
*/
	ent[7] = 8 - (rb - b*8);
	cipher_idea((word16 *) ent,(word16 *) sal,z);
        if(write(f2,sal,8)!=8) {
            printf("Error al escribir en archivo %s\n",nomvec);
            exit(-1);
        }
    	close(f1);
    	close(f2);
}
