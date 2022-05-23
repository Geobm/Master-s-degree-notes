/* DemoRC2.h - Demo para RC2.

   Universidad Nacional Autonoma de Mexico
*/
#include <stdio.h>
#include <string.h>
#include "RC2.h"

// vamos a jugar con estas llaves
B8 Key1[8]  = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
B8 Ptx1[8]  = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};



B8 Key2[8]  = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
B8 Ptx2[8]  = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
B8 Key3[16] = {0x88,0xbc,0xa9,0x0e,0x90,0x87,0x5a,0x7f,
               0x0f,0x79,0xc3,0x84,0x62,0x7b,0xaf,0xb2};

int main(int argc,char *argv[])
{
    FILE *file;
    int i, nbytes, longSal;
    B8 *ap;
    B16 Ky[64];

	ExpandeLlave(Ky,Key1,8,64);
    file= fopen(argv[1],"r");
    RC2_Cifra(file,Ky); // "r" for read,Ky);	

	//-----------------------------------Descifrar------------------------------------------------------
    RC2_Descifra("Ecrypted.cif",Ky);
    
}

/* Rutina para el cifrado de un bloque de datos de
   longitud variable.
   Entrada:
	EntySal, un buffer de bytes de longuitud longEnt.
	K, La llave expandida que se usara en el cifrado.
   Salida:
        EntySal, un buffer de bytes de longuitud longSal.
   Observacion: El archivo de entrada y salida es el mismo.
*/
void RC2_Cifra(nombreArchivo,K)
char nombreArchivo[];
B16 K[];
{
	
	//B8 EntySal[65421];
	int longEnt;
	
	FILE *fp;
	long lSize;
	

	fp = fopen ( nombreArchivo , "rb" );
	if( !fp ) perror(nombreArchivo),exit(1);
	
	fseek( fp , 0 , SEEK_END);
	lSize = ftell( fp );
	fseek( fp , 0 , SEEK_SET);
	
	longEnt = lSize;
	int i, longPad=8-(longEnt%8), numBloques, longSal;
    unsigned char *Ptx;
	
        
	/* allocate memory for entire content */
	longSal = longEnt + longPad;  /* La longitud del buffer por cifrar. */
	B8 buffer[longSal];
	
	/* copy the file into the buffer */
	fread( buffer , lSize, 1 , fp);
	fclose(fp);
	
	for(i=0;i<longPad;i++){buffer[longEnt+i] = (unsigned char) longPad;} // agrega el padding
	
	//-------------------------------------------------------------------------------------------------------
    

   
    
    numBloques = (longSal) >> 3;  /* Núm. de bloques por cifrar. */
    /* ¡A cifrar! */
    for(i=0,Ptx=buffer;i<numBloques;i++,Ptx+=8){
        RC2_CifraBloque((B16 *)Ptx,K);
        printf("ptx es %s\n", Ptx);
    }
	//--------------------------------------------------------------------------------------------------------


    //escribir
    FILE *fichCifSal;
    fichCifSal=fopen("Ecrypted.cif","ab");
    fwrite((char *)buffer,longSal,1,fichCifSal);
    fclose(fichCifSal);
}

/* Rutina para el descifrado de un bloque de datos de
   longitud variable.
   Entrada:
        EntySal, un buffer de bytes de longuitud longEnt.
        K, La llave expandida que se usara en el descifrado.
   Salida:
        EntySal, un buffer de bytes de longuitud longSal.
   Observacion: El archivo de entrada y salida es el mismo.
*/
void RC2_Descifra(nombreArchivo,K)
char nombreArchivo[];
B16 K[];
{
    int i, numBloquesD, longSal, longEntD;
    unsigned char *Ptx;

	FILE *fp;
	long lSize;
	
	fp = fopen ( nombreArchivo , "rb" );
	
	fseek( fp , 0 , SEEK_END);
	lSize = ftell( fp );
	fseek( fp , 0 , SEEK_SET);
	
	longEntD = lSize;	
        
	/* allocate memory for entire content */
	
	B8 bufferD[longSal];
	
	/* copy the file into the bufferD */
	fread( bufferD , lSize, 1 , fp);
	fclose(fp);
	
	//------------------------------------------------------------------------------------------
    numBloquesD = longEntD >> 3;  /* Núm. de bloques por descifrar. */
    /* ¡A descifrar! */
    for(i=0,Ptx=bufferD;i<numBloquesD;i++,Ptx+=8)
        RC2_DescifraBloque((B16 *)Ptx,K);
    longSal = longEntD - (unsigned int) *(Ptx-1);  /* Quitamos padding. */
    //------------------------------------------------------------------------------------------
    
    
    
    FILE *fichDescifSal;
    fichDescifSal=fopen("real.txt","ab");
    fwrite((char *)bufferD,longSal,1,fichDescifSal);
    fclose(fichDescifSal);
}

/* Rutina de expancion de la llave;
   salida: EKey, la llave expandida.
   entrada: Key, la llave por expander.
            t, número de bytes en la llave.
            t1, número de bits efectivos en la llave.
*/
void ExpandeLlave(EKey,Key,t,t1)
B16 *EKey;
B8 *Key;
int t, t1;
{
    int i, T8=((t1+7)/8);
    int TM=(255 % (1 << (8+t1-8*T8)));
    B8 *Ly = (B8 *) EKey;

    memcpy(Ly,Key,t);   /* Inicializa EKey */
    /* Primer loop, ver RFC2268 p. 3. */
    for(i=t;i<128;i++) Ly[i] = PITABLE[(Ly[i-1]+Ly[i-t])&0xff];
    /* Paso intermedio. */
    Ly[128-T8] = PITABLE[Ly[128-T8]&TM];
    /* Segundo loop. */
    for(i=127-T8;i>=0;i--) Ly[i] = PITABLE[Ly[i+1]^Ly[i+T8]];
}

/* Rutina para cifrar un bloque usando RC2.
   parámetros: R el bloque de 64 bits a cifrar y la llave
   expandida K que habrá de usarse. La salida i.e. el bloque
   cifrado estará en R.
*/
void RC2_CifraBloque(R,K)
B16 R[],K[];
{
    int j=0,cnr,im;
    B8 S[4]={0x01,0x02,0x03,0x05};

    Mix(R,K,j,5);
    Mash(R,K);
    Mix(R,K,j,6);
    Mash(R,K);
    Mix(R,K,j,5);
}

/* Rutina para descifrar un bloque usando RC2.
   parámetros: R el bloque de 64 bits a descifrar y la llave
   expandida K que habrá de usarse. La salida i.e. el bloque
   descifrado estará en R.
*/
void RC2_DescifraBloque(R,K)
B16 R[],K[];
{
    int j=63,cnr,im;
    B8 S[4]={0x01,0x02,0x03,0x05};

    R_Mix(R,K,j,5);
    R_Mash(R,K);
    R_Mix(R,K,j,6);
    R_Mash(R,K);
    R_Mix(R,K,j,5);
}


