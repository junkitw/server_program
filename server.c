/* A simple server in the internet domain using TCP
The port number is passed as an argument 


 To compile: gcc server.c -o server 
*/

/* Name: Jun Kit Wong	This code was a product of my individual effort built upon the source code given by Renlord.
   Student ID: 731740
   COMP30023
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include "uint256.h"
#include "sha256.h"

typedef struct queue {
	int socketID;
	char incoming[256];
	char address[INET6_ADDRSTRLEN];
	char *outgoing;
	struct queue* next;
} queue_t;

typedef struct client {
	int* socketID;
	char address[INET6_ADDRSTRLEN];
} client_t;

void* connection_handler(void* sock);
void* identify_header(int sock_desc, char* buffer, client_t* clientinfo);
int solution_manager(char* soln);
char* concat_solution(char* seed, char* nonce);
void* calculate_target(BYTE* target, char* diff);
char* work_solution(char* buffer);
void hash_func(BYTE* output, BYTE* input);
void* processing_queue();
void* open_and_print_to_file(int side, char* message, int sockID, char* address);
queue_t* initialize_queue(int sock, char address[INET6_ADDRSTRLEN], char* data);
queue_t* insertAtTail(queue_t **head, queue_t *current);
queue_t* pop_node(queue_t **head);
void deleteKey(queue_t **head, int sock);

queue_t *worker = NULL;
pthread_t computation_work;
pthread_mutex_t lock_work;

int main(int argc, char **argv)
{
	int permiss = 1;
	time_t curr_time;
	struct tm *timeinfo;
	int sockfd, newsockfd, portno, clilen;
	struct sockaddr_in serv_addr, cli_addr;
	pthread_t multi_thread;
	int* new_sock;
	FILE* log;

	remove("log_file.txt");

	if (argc < 2) 
	{
		fprintf(stderr,"ERROR, no port provided\n");
		exit(1);
	}

	 /* Create TCP socket */
	
	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if (sockfd < 0) 
	{
		perror("ERROR opening socket");
		exit(1);
	}

	
	bzero((char *) &serv_addr, sizeof(serv_addr));

	portno = atoi(argv[1]);
	
	/* Create address we're going to listen on (given port number)
	 - converted to network byte order & any IP address for 
	 this machine */
	
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(portno);  // store in machine-neutral format

	 /* Bind address to the socket */
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &permiss, sizeof(int));
	if (bind(sockfd, (struct sockaddr *) &serv_addr,
			sizeof(serv_addr)) < 0) 
	{
		perror("ERROR on binding");
		exit(1);
	}
	
	/* Listen on socket - means we're ready to accept connections - 
	 incoming connection requests will be queued */
	
	listen(sockfd,100);
	
	clilen = sizeof(cli_addr);

	if(pthread_create(&computation_work, NULL, processing_queue, (void*)NULL) < 0){
		perror("failed to create work thread");
		exit(1);
	}

	/* Accept a connection - block until a connection is ready to
	 be accepted. Get back a new file descriptor to communicate on. */

	while(newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen)) {
		
		client_t clientinfo;
		clientinfo.socketID = malloc(1);
		new_sock = malloc(1);
		*new_sock = newsockfd;
		*clientinfo.socketID = newsockfd;

		inet_ntop(AF_INET, (struct sockaddr *)&cli_addr.sin_addr, clientinfo.address, sizeof clientinfo.address);
		if(pthread_create(&multi_thread, NULL, connection_handler, (void*)&clientinfo) < 0) {
            perror("could not create thread");
            return 1;
        }
	}

	if (newsockfd < 0) {
		perror("ERROR on accept");
		exit(1);
	}
	
	fclose(log);

	return 0; 
}

void* connection_handler(void* sock) {
	time_t curr_time;
	struct tm *timeinfo;
	client_t *clientinfo;
	int sock_desc, read_size;
	unsigned int i;
	char *temp, rbuff[256], buffer[256];
	int flag = 0, start = 0;
	FILE* log;
	temp = malloc(sizeof(char)*256);

	clientinfo = sock;
	sock_desc = (int)*clientinfo->socketID;
	log = fopen("log_file.txt", "ab+");
	time(&curr_time);
	timeinfo = localtime(&curr_time);
	fprintf(log, "%.24s || clientID: %d IP: || Connection Successful.\n", asctime(timeinfo), clientinfo->address, *clientinfo->socketID);
	
	fclose(log);

	bzero(rbuff, 256);
	bzero(buffer, 256);
 
	while((read_size = recv(sock_desc , rbuff , 512 , 0)) > 0 ) {
   	
		for(i = 0; i < strlen(rbuff); i++) {
			
			buffer[start] = rbuff[i];

			if(buffer[start] == '\r') {
				flag = 1;
			}

			if(buffer[start] == '\n' && flag == 1) {
				
				open_and_print_to_file(0, buffer, sock_desc, clientinfo->address);

				identify_header(sock_desc, buffer, clientinfo);
				start = -1;
			}

			start++;
		}
		bzero(rbuff, 256);
	}

	log = fopen("log_file.txt", "ab+");
	fprintf(log, " ========== clientID: %d disconnected ========== \n", sock_desc);
	fclose(log);
	close(sock);
}

void* identify_header(int sock_desc, char* buffer, client_t* clientinfo) {
	char* temp;

	if(strcmp(buffer, "PING\r\n") == 0) {
		temp = "PONG\r\n";
		write(sock_desc, temp, 6);
		open_and_print_to_file(1, temp, sock_desc, clientinfo->address);
	}

	else if(strcmp(buffer, "PONG\r\n") == 0) {
		temp = "ERRO: PONG strictly reserved for server responses\r\n";
		write(sock_desc, temp, 40);
		open_and_print_to_file(1, temp, sock_desc, clientinfo->address);
	}

	else if(strcmp(buffer, "OKAY\r\n") == 0) {
		temp = "ERRO: NOT okay to send OKAY to server\r\n";
		write(sock_desc, temp, 40);
		open_and_print_to_file(1, temp, sock_desc, clientinfo->address);
	}


	else if(strncmp(buffer, "SOLN", 4) == 0) {
		if(solution_manager(buffer) == 1) {
			temp = "OKAY\r\n";
			write(sock_desc, temp, 6);
			open_and_print_to_file(1, temp, sock_desc, clientinfo->address);
		}

		else {
			temp = "ERRO: INVALID SOLN\r\n";
			write(sock_desc, temp, 40);
			open_and_print_to_file(1, temp, sock_desc, clientinfo->address);
		}
	}

	else if(strncmp(buffer, "WORK", 4) == 0) {
		queue_t *job = initialize_queue(sock_desc, clientinfo->address, buffer);
		worker = insertAtTail(&worker, job);
	}

	else if(strcmp(buffer, "ABRT\r\n") == 0) {
		temp = "OKAY\r\n";
		write(sock_desc, temp, 6);
		open_and_print_to_file(1, temp, sock_desc, clientinfo->address);
		pthread_cancel(computation_work);
		if(pthread_create(&computation_work, NULL, processing_queue, (void*)NULL) < 0){
			perror("Failed to recreate thread to do WORK computation");
			exit(1);
		}
		deleteKey(&worker, sock_desc);
	}

	else {
		temp = "ERRO: Invalid Message\r\n";
		write(sock_desc, temp, 40);
		open_and_print_to_file(1, temp, sock_desc, clientinfo->address);
	}

	return temp;
}

int solution_manager(char* soln) {
	int i;
	char* diff;
	char* seed;
	char* nonce;
	char* concatenated;
	BYTE soln_byte[40];
	int start = 0;
	char temp[3];
	BYTE target[32];
	BYTE hashed[32];
	char replace[256];
	
	seed = malloc(sizeof(char) * 256);
	diff = malloc(sizeof(char) * 256);
	nonce = malloc(sizeof(char) * 256);
	concatenated = malloc(sizeof(char) * 256);

	strcpy(replace, soln);
	sscanf(replace, "SOLN %s %s %s\r\n", diff, seed, nonce);
	
	concatenated = concat_solution(seed, nonce);

	for(i = 0; i < strlen(concatenated); i+=2) {
		temp[0] = concatenated[i];
		temp[1] = concatenated[i+1];
		temp[2] = '\0';

		soln_byte[start] = (BYTE)(strtol(temp, NULL, 16));
		start++;
	}
	uint256_init(hashed);
	uint256_init(target);

	hash_func(hashed, soln_byte);

	calculate_target(target, diff);

	if(sha256_compare(hashed, target) == -1) {
		return 1;
	}

	else {
		return 0;
	}

}

char* concat_solution(char* seed, char* nonce) {
	char* temp;
	temp = strcat(seed, nonce);
	return temp;
}

void* calculate_target(BYTE* target, char* diff) {
	BYTE gamma[32];
	BYTE result[32];
	BYTE two[32];
	long ret;
	uint32_t alpha, power;
	int i;
	int k, l;
	k = 31;

	uint256_init(gamma);
	uint256_init(two);
	uint256_init(result);
	uint256_init(target);
	
	two[31] = 2;

	ret = strtol(diff, NULL, 16);
	alpha = ret>>24;


	char *p = diff += 2;

	for(i = 29; i<32; i++) {
		sscanf(p, "%2x", &gamma[i]);
		p +=2;
	}
	
	power = 8*(alpha-3);


	uint256_exp(result, two, power);


	uint256_mul(target, result, gamma);

}

char* work_solution(char* soln) {
	
	int i;
	int stop = 0;
	char* diff;
	char* seed;
	long unsigned int nonce;
	char* worker_count;
	char* concatenated;
	char* temp_nonce;
	char* solution_string;
	char* answer;

	answer = malloc(sizeof(char) * 256);
	solution_string = malloc(sizeof(char) * 256);
	seed = malloc(sizeof(char) * 256);
	diff = malloc(sizeof(char) * 256);
	temp_nonce = malloc(sizeof(char) * 256);
	worker_count = malloc(sizeof(char) * 256);
	strcpy(answer, soln);

	sscanf(answer, "WORK %s %s %lx %s\r\n", diff, seed, &nonce, worker_count);

	sprintf(temp_nonce, "%lx", nonce);

	while(stop == 0) {
		bzero(solution_string, 256);
		snprintf(solution_string, 256, "SOLN %s %s %s", diff, seed, temp_nonce);
		if(solution_manager(solution_string) == 0) {
			nonce++;
			bzero(temp_nonce, 256);
			sprintf(temp_nonce, "%lx", nonce);
		}
		else {
			stop = 1;
			printf("%s\n", solution_string);
		}
	}
	return solution_string;
}

void hash_func(BYTE* output, BYTE* input) {
	BYTE buf[32];
	SHA256_CTX ctx;


	uint256_init(buf);

	sha256_init(&ctx);
	sha256_update(&ctx, input, 40);
	sha256_final(&ctx, buf);

	sha256_init(&ctx);
	sha256_update(&ctx, buf, 32);
	sha256_final(&ctx, output);
}

queue_t* initialize_queue(int sock, char address[INET6_ADDRSTRLEN], char* data) {
	queue_t *temp = (queue_t*)malloc(sizeof(struct queue));
	strcpy(temp->incoming, data);
	temp->socketID = sock;
	strcpy(temp->address, address);
	temp->next = NULL;
	return temp;
}

queue_t* insertAtTail(queue_t **head, queue_t *current) {
	if(*head==NULL){
		return current;
	}
	else{
		(*head)->next = insertAtTail(&(*head)->next, current);
		return *head;
	}
}

queue_t* pop_node(queue_t **head) {
	queue_t *temp = *head;
    if (temp) {
        *head = temp->next;
    }
	return temp;
}

void deleteKey(queue_t **head, int sock) {
    
    queue_t* temp = *head, *prev;
 
   
    while (temp != NULL && temp->socketID == sock)
    {
        *head = temp->next;  
        free(temp);              
        temp = *head;
    }
 
 
    while (temp != NULL)
    {
        
        while (temp != NULL && temp->socketID != sock)
        {
            prev = temp;
            temp = temp->next;
        }
 
  
        if (temp == NULL) return;
 
        
        prev->next = temp->next;
 
        free(temp); 
 
      
        temp = prev->next;
    }
}

void* processing_queue() {
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	while(1) {
		if(worker != NULL){
			pthread_mutex_lock(&lock_work);
			queue_t* first = pop_node(&worker);
			pthread_mutex_unlock(&lock_work);
			first->outgoing = work_solution(first->incoming);
			write(first->socketID, first->outgoing, 97);
			open_and_print_to_file(1, strcat(first->outgoing, "\r\n"), first->socketID, first->address);
		}
	}
}

void* open_and_print_to_file(int side, char* message, int sockID, char* address) {
	time_t curr_time;
	struct tm *timeinfo;
	FILE* log;

	log = fopen("log_file.txt", "ab+");
	time(&curr_time);
	timeinfo = localtime(&curr_time);
	if(side == 1) {
		fprintf(log, "%.24s || server 0.0.0.0 || SERVER -----> CLIENT (clientID: %d), MESSAGE: %s \n", asctime(timeinfo), sockID, message);
	}

	else {
		fprintf(log, "%.24s || IP: %s (clientID: %d) CLIENT -----> SERVER || MESSAGE: %s\n", asctime(timeinfo), address, sockID , message);
	}

	fclose(log);
}
