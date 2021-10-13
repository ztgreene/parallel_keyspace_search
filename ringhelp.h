/*****************************************************************
* These are helper functions to build the ring for computation
* and allow communication between nodes
*****************************************************************/
#define ringhelp_h 

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define BUFFSIZE 32

//Ring functions
int parse_args(int argc,  char *argv[ ], int *np){
  if ( (argc != 5) || ((*np = atoi (argv[1])) <= 0) ) {
    fprintf (stderr, "Usage: %s nprocs\n", argv[0]);
    return(-1); };
  return(0); 
}

int make_trivial_ring(){   
  int   fd[2];
  if (pipe (fd) == -1) {
    return(-1);} 
  if ((dup2(fd[0], STDIN_FILENO) == -1) ||
      (dup2(fd[1], STDOUT_FILENO) == -1)) {
        return(-2); }
  if ((close(fd[0]) == -1) || (close(fd[1]) == -1)){   
    return(-3); }
  return(0); 
}

int add_new_node(int *pid){
  int fd[2];
  if (pipe(fd) == -1) 
    return(-1); 
  if ((*pid = fork()) == -1)
    return(-2); 
  if(*pid > 0 && dup2(fd[1], STDOUT_FILENO) < 0)
    return(-3); 
  if (*pid == 0 && dup2(fd[0], STDIN_FILENO) < 0)
    return(-4); 
  if ((close(fd[0]) == -1) || (close(fd[1]) == -1)) 
    return(-5);
  return(0);
}


//For getting the key (string) from previous node 
void get_key(char message[], char *keys)
{
  if((keys == NULL)) return;
  if(read(STDIN_FILENO, message, BUFFSIZE) > 0)
  {
    for (int i = 0; i < strlen(keys); i++)
    {
      // Access each char in the string
        keys[i] = keys[i];
    } 
  }
  else {
    keys = 0;
  }
}
//For sending key (or string) to next node
int send_key(char message[], char* keys){
  int bytes, len;
  sprintf(message, "%s ", keys);
  len = strlen(message) + 1;
  if((bytes = write(STDOUT_FILENO, message, len)) != len){
    fprintf(stderr, 
            "Write of %d bytes failed, only sent %d bytes\n",
            len, bytes);
    return -1; 
  } else {
    return bytes;
  }
}