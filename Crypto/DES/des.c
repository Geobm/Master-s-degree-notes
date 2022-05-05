/*	archivo : des.c
	Programa principal para cifrar y descifrar usando DES.

	Uso : $ des [-c | -d | -e | -p] L1 L2 ARCHIVO
		-c : para cifrar
		-d : para descifrar sin borrar ARCHIVO.cif
	        -e : para descifrar borrando ARCHIVO.cif
		-p : para descifrar con salida a la pantalla
	        L1 y L2 : 7 digitos hexadecimales c/u (56 bits de la llave maestra)
		ARCHIVO : archivo a cifrar o descifrar

	Nota 1 : Si la opcion es -c, entonces el programa generara el archivo
	         cifrado ARCHIVO.cif borrado ARCHIVO. Si la opcion es -d, se 
		 descifrara el ARCHIVO.cif en ARCHIVO. La opcion -e es igual
		 a -d solo que al final es borrando ARCHIVO.cif. Por ultimo si 
		 la opcion es -p, entonces no se genera ningun archivo de salida
		 y el descifrado sera a la pantalla.

	Nota 2 : Esta implementacion tiene caracter de experimental y si esta
		 se usa en aplicaciones reales, es conveniente modificarle
		 de tal manera que la llave maestra (L1 y L2) NO sea ingresada
		 al programa como parte de los argumentos.

	M. en C. Gerardo Vega H.                          14 de febrero de 1997     */

#include <string.h>

#include <stdio.h>
#include "des_def.h"     /* Declaracion de constantes tipos y macros para el des.c */
#include "des_var.h"     /* " de variables globales y de las tablas S_P y PC2_Tab */
#include <stdlib.h>

#define swap(value) ((0x000000ff & value) << 24) | ((0x0000ff00 & value) << 8) | \
                       ((0x00ff0000 & value) >> 8) | ((0xff000000 & value) >> 24) 

int main(argc, argv)
int argc;
char *argv[];
{
	procesa_argv(argc,argv);          	/* Procesa los argumentos */
	genllaves();                      	/* Genera las subllaves */
	cifra_o_descifra();		  	/* Cifra o descifra */
	fclose(fpe); fclose(fps);
	if((!pantalla) && borrar) remove(ent);
}

void procesa_argv(argc, argv)
int argc;
char *argv[];
{
	if(argc!=5) uso();
        strcpy(ent,argv[4]);    strcpy(sal,argv[4]);
	if(argv[1][0]=='-') {
	    switch(argv[1][1]) {
		case 'c':
		    strcat(sal,".cif");
		    break;
		case 'd':
		case 'e':
		    cifrar = FALSE;
		    if(strcmp(".cif",&ent[strlen(argv[4])-4])) strcat(ent,".cif");
		    else sal[strlen(argv[4])-4] = 0;
		    if(argv[1][1]=='d') borrar = FALSE;
		    break;
		case 'p':
		    cifrar = FALSE;
		    if(strcmp(".cif",&ent[strlen(argv[4])-4])) strcat(ent,".cif");
		    pantalla = TRUE;
		    fps = stdout;			/* La salida a la pantalla */
		    break;
		default:
		    fprintf(stderr,"DES-Error: opcion ilegal %c\n",argv[1][1]);
		    exit(1);
	    }
	} else uso();
	llave[0] = strtol(argv[2],(char **)NULL,16);	/* 56 bits de la llave */
	llave[1] = strtol(argv[3],(char **)NULL,16);    /* maestra (14 digitos hexa) */
 
        { int i;
        for(i=0;i<8;i++) printf("B8: %2x ",((B8 *)llave)[i]); printf("\n");
        }

	if((fpe = fopen(ent,"r"))==NULL) {
	    fprintf(stderr,"DES-Error: no puedo abrir %s\n",ent);
	    exit(1);
	}
	if(!pantalla) 
            if((fps = fopen(sal,"w"))==NULL) {
                fprintf(stderr,"DES-Error: no puedo abrir %s\n",sal);
                exit(1);
            }
}

void uso()
{
	printf("\nUso : $ des [-c | -d | -e | -p] L1 L2 ARCHIVO\n");
	printf("	-c : para cifrar\n");
	printf("	-d : para descifrar sin borrar ARCHIVO.cif\n");
	printf("        -e : para descifrar borrando ARCHIVO.cif\n");
	printf("	-p : para descifrar con salida a la pantalla\n");
	printf("        L1 y L2 : 7 digitos hexadecimales c/u (56 bits de la llave maestra)\n");
	printf("	ARCHIVO : archivo a cifrar o descifrar\n");
	printf("Ejemplo : des -c a23bcd7 54e71f0 nomina\n\n");

	printf("Nota : Si la opcion es -c, entonces el programa generara el archivo\n");
	printf("       cifrado ARCHIVO.cif borrado ARCHIVO. Si la opcion es -d, se \n");
	printf("       descifrara el ARCHIVO.cif en ARCHIVO. La opcion -e es igual\n");
	printf("       a -d solo que al final es borrando ARCHIVO.cif. Por ultimo si\n");
	printf("       la opcion es -p, entonces no se genera ningun archivo de salida\n");
	printf("       y el descifrado sera a la pantalla.\n\n");
	exit(0);
}

void genllaves()
{
	int i,j;

	for(i=0,j=(cifrar)?0:ITER-1;i<ITER;i++,j+=(cifrar)?1:-1) {
	    llave[0] = Rota(llave[0],LS[i]);  	/* Rota la llave maestra para */
	    llave[1] = Rota(llave[1],LS[i]);  	/* obtener la siguiente subllave */
	    subllaves[j][0] = (PC2_Tab_0[((B8 *)llave)[3]] | 
			       PC2_Tab_1[((B8 *)llave)[2]] | /* Obtiene las subllaves */
	    	               PC2_Tab_2[((B8 *)llave)[1]] | /* directamente a traves */
		       	       PC2_Tab_3[((B8 *)llave)[0]]); /* de las tablas PC2_Tab */
	    subllaves[j][1] = (PC2_Tab_4[((B8 *)llave)[7]] | 
			       PC2_Tab_5[((B8 *)llave)[6]] |
		               PC2_Tab_6[((B8 *)llave)[5]] | 
			       PC2_Tab_7[((B8 *)llave)[4]]);
            printf("%8x  %8x\n",subllaves[j][0],subllaves[j][1]);   
	}
}
	
void cifra_o_descifra()
{
	int register i;
	B32 register I, D,           /* Parte izquierda y derecha en cada iteracion */
		     izq, der,       /* " " " del resultado de E ^ la subllave */ 
		     F_res;          /* Resultado de la funcion F */
	B32 text[2];
	while(1) {				      /* Hasta terminar de leer */
	    if((i=fread((char *)text,1,8,fpe))!=8) {  /* Lee bloque de 64 bits */
		if(i==0) break;                       /* Termino de leer, todo bien */
		else if((i>0)&&(i<8)) 
			 for(;i<8;i++) ((char *)text)[i] = 0;             /* Relleno */
		     else {			      /* Hubo un error en la lectura */
		         fprintf(stderr,"DES-Error: Error al leer del archivo\n");
			 exit(1);
		     }
	    }
	    I = swap(text[0]);  D = swap(text[1]);  /* El bloque de 64 bit en 2 de 32 bits (I,D) */
            printf("I=%8x  D=%8x\n",I,D);  
	    for(i=0;i<ITER;i++) {
		izq = subllaves[i][0] ^ E_izq(D);  /* Xor la subllave con la salida */
		der = subllaves[i][1] ^ E_der(D);  /* de la funcion de expancion E */
		F_res = I ^ F_sal(izq, der);       /* Las cajas S y la permutacion P */
		I = D;				   /* Crusa los subloques de 32 bits */
		D = F_res;
	    }
	    text[0] = swap(D);  text[1] = swap(I);
	    if(fwrite((char *)text,1,8,fps)!=8) {  /* Escribe el bloque cifrado */
		fprintf(stderr,"DES-Error: Error al escribir al archivo\n");
		exit(1);
	    }
	}
}

