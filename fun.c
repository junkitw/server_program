#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int valid_arguments(char* args);


int main(int argc, char **argv)
{
	int count = 0;
	char temp[256] = "WORK 1fffffff 0000000019d6689c085ae165831e934ff763ae46a218a6c172b3f1b60a8ce26f 1000000023212000 01";
	printf("%s\n", temp);

	count = valid_arguments(temp);
	
	printf("%d\n", count);
	return 0;
}


int valid_arguments(char* args) {
	
	char *token;
	token = strtok(args, " ");
	int i;

	while(token != NULL) {
		
		token = strtok(NULL, " ");
		i++;
	}

	return i;

}