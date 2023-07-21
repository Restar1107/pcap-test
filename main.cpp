#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <netinet/in.h>

u_int32_t *	get(u_int32_t *n1, char *argv[2]);
u_int32_t 	plus(u_int32_t a, u_int32_t b);

int main(int argc, char* argv[]){
	//if (argc != 3)
	//	return 0;
	
	//new
	u_int32_t n[2] = {0,};
	printf("%d\n", argc);
	u_int32_t result = 0;
	FILE * f[2] = {0,};
	for (int i = 1; i < argc; i ++){
		f[i-1] = fopen(argv[i], "r");
		fread(&n[i-1] ,8, 1, f[i-1]);	
		printf("sscanf: %u\n", n[i-1]);
		printf("for loop %p\n",n+i-1);
		result += ntohl(n[i-1]);
		fclose(*(f+i-1));
	}
	printf("%d\n", result);
	
}
