
#define ITER 16
#define TRUE 1
#define FALSE 0

typedef int BOOLEAN;
typedef unsigned long int B32;
typedef unsigned char B8;

/* 
 * 		Macros para la funcion de Expancion E
 *
 * 		Estas dos macros comen 32 bit's de D. Aqui se esta considerando
 * 		que el bit numero 1 y el mas significativo es el del extremo izquierdo.
 * 		Consecuentemente el bit 32 y el menos significativo es el del extremo
 * 		derecho. Estas macros entregan c/u 4 grupos de 6 bits c/u, con los cuales
 * 		se forman los 8 grupos de 6 bits los que, como se sabe, son las entradas a las
 * 		8 cajas S. Estos 8 grupos de bits se encuentraran distribuidos de la siguiente
 * 		manera:
 *
 * 			Grupo              bits		en la palabra de salida de
 * 				  1	            3-8			E_izq
 * 				  	  2		   11-16		E_izq
 * 				  	  	  3	 	   19-24		E_izq
 * 				  	  	  	  4		   27-32		E_izq
 * 				  	  	  	  	  5	            3-8			E_der
 * 				  	  	  	  	  	  6		   11-16		E_der
 * 				  	  	  	  	  	  	  7	 	   19-24		E_der
 * 				  	  	  	  	  	  	  	  8		   27-32		E_der
 *
 * 				  	  	  	  	  	  	  	  Los bits 1,2,9,10,17,18,25,26 de ambas palabras de salida NO son usadas y
 * 				  	  	  	  	  	  	  	  no tienen ningun significado.
 * 				  	  	  	  	  	  	  	  */

#define E_izq(D) (((D&0x001f8000)>>15) | ((D&0x01f80000)>>11) | \
				  ((D&0x1f800000)>>7) | (((D>>3)&0x1f000000) | \
					  		  ((D<<29)&0x20000000)))

#define E_der(D) (((D&0x0001f800)<<13) | ((D&0x00001f80)<<9) | \
				  ((D&0x000001f8)<<5) | (((D>>31)&0x00000001) | \
					  		  ((D<<1)&0x0000003e)))
/*
 * 		Salida final de la funcion F
 *
 * 		Observe que las cajas S y la permutacion P son evaluadas directamente
 * 		a traves de la tabla S_P, la cual fue precalculada con el programa 
 * 		tablas.c que se encuentra en des_var.h.
 * 		*/

#define F_sal(izq,der) (S_P[0][(B8)(izq>>24)] | S_P[1][(B8)(izq>>16)] | \
					S_P[2][(B8)(izq>>8)]  | S_P[3][(B8)izq] | \
								S_P[4][(B8)(der>>24)] | S_P[5][(B8)(der>>16)] | \
											S_P[6][(B8)(der>>8)]  | S_P[7][(B8)der])

		/* Rotacion para gererar las subllaves */
#define Rota(LL,nb) ((LL>>(28-nb)) | (LL<<nb)) & 0x0fffffff

void genllaves();                   /* Rutina para generar las subllaves */
void cifra_o_descifra();            /* Rutina general para cifrar o desifrar */
void uso();			    /* sintaxis y explicacion del uso */
void procesa_argv();                /* procesa los argumentos */

