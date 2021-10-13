/******************************************************************************
 * parallel_search_keyspace.c
 * Simple program that demonstrates the use of the openSSL library functions
 * to brute-force search for an AES encryption key given a partial key. This
 * is a splendid multi-process version that demonstrates the operations needed
 * to complete the search

 * Parameters:
 *     1. The number of processes to use
 *     2. The partial key to use for the search
 *     3. The cipher you are using (in *.txt format)
 *     4. The plain text (in *.txt format)
 * 
 * Returns: 0 on Success
 * 
 * Build: 
 *     gcc -Wall -pedantic -lcrypto parallel_search_keyspace.c -o 
 *        parallel_search_keyspace
 * 
 * Run Example:
 * parallel_search_keyspace 5 B1AF2507B69F11CCB3AE2C3592039
 *                                             example_cipher.txt plain.txt
 * 
 * ***************************************************************************/
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#include "ringhelp.h"     // Library of functions for using ring
#include "aesfunctions.h" // Library with aes functions

#include <sys/types.h> // for wait
#include <sys/wait.h>  // for wait 

/*****************************************************************************
 * Function: main   
 * 
 * 
 * Parameters: 
 *     1. The number of processes
 *     2. The key to use for encryption
 *     3. The name for the cipher text file 
 *     4. The name for the plain text file
 * 
 * Returns: 0 on Success, key printed to stdout
 * 
 ****************************************************************************/
int
main (int argc, char **argv)
{
  unsigned char *key_data;       //Pointers to key data location
  int key_data_len, i;           //Key length
  char *plaintext;               //Pointer to plain text

  unsigned char key[32];
  unsigned char trialkey[32];

  int cipher_length, plain_length;

  key_data = (unsigned char *) argv[2];
  key_data_len = strlen (argv[2]);

  // Read encrypted bytes from file
  FILE *mycipherfile;
  mycipherfile = fopen (argv[3], "r");
  fseek (mycipherfile, 0, SEEK_END);
  cipher_length = ftell (mycipherfile);
  rewind (mycipherfile);
  unsigned char cipher_in[cipher_length];
  fread (cipher_in, cipher_length, 1, mycipherfile);
  fclose (mycipherfile);

  // Read decrypted bytes(to cross reference key results) from file
  FILE *myplainfile;
  myplainfile = fopen (argv[4], "r");
  fseek (myplainfile, 0, SEEK_END);
  plain_length = ftell (myplainfile);
  rewind (myplainfile);
  char plain_in[plain_length];
  fread (plain_in, plain_length, 1, myplainfile);
  fclose (myplainfile);

  int y;
  fprintf (stderr, "\nPlain:");
  for (y = 0; y < plain_length; y++)
    {
      fprintf (stderr, "%c", plain_in[y]);
    }
  fprintf (stderr, "\n");

  fprintf (stderr, "Ciphertext: %s\n\n", (char *) cipher_in);

  //Condition known portion of key
  //Only use most significant 32 bytes of data if > 32 bytes
  if (key_data_len > 32)
    key_data_len = 32;

  //Copy bytes to the front of the key array
  for (i = 0; i < key_data_len; i++)
    {
      key[i] = key_data[i];
      trialkey[i] = key_data[i];
    }

  //If the key data < 32 bytes, pad the remaining bytes with 0s
  for (i = key_data_len; i < 32; i++)
    {
      key[i] = 0;
      trialkey[i] = 0;
    }

  //This code packs the last 8 individual bytes of the key into an
  //unsigned long-type variable that can be easily incremented 
  //to test key values.
  unsigned long keyLowBits = 0;
  keyLowBits = ((unsigned long) (key[24] & 0xFFFF) << 56) |
    ((unsigned long) (key[25] & 0xFFFF) << 48) |
    ((unsigned long) (key[26] & 0xFFFF) << 40) |
    ((unsigned long) (key[27] & 0xFFFF) << 32) |
    ((unsigned long) (key[28] & 0xFFFF) << 24) |
    ((unsigned long) (key[29] & 0xFFFF) << 16) |
    ((unsigned long) (key[30] & 0xFFFF) << 8) |
    ((unsigned long) (key[31] & 0xFFFF));

  int trial_key_length = 32;
  unsigned long maxSpace = 0;

  //Work out the maximum number of keys to test
  maxSpace = ((unsigned long) 1 << ((trial_key_length - key_data_len) * 8)) -1;




/* Here are variables used to divide the search-space and pass the key
****************************************************************************/
  char message[BUFFSIZE];                 //Buffer for communicating keys
  int p;                                  //The number of the process
  unsigned long counter;                  //Tracks number of the attempt
  unsigned long domainMax;         //The maximum key child process will search
  int childpid;                           //Process should spawn another
  int nprocs = atoi(argv[1]);             //Number of processes in ring
  unsigned long jobSize = (maxSpace/nprocs);  //partitioning work
  unsigned long remainder = (maxSpace%nprocs);//remainder from division

  fprintf(stderr, "\nNumber of processes: %d\n", nprocs);
  fprintf(stderr, "Keyspace parallelised as follows:\n");

/*This builds ring for computation
****************************************************************************/
  if(parse_args(argc,argv,&nprocs) < 0)
  {
    fprintf(stderr, "parse args failed");
    exit(EXIT_FAILURE);
  }

  if(make_trivial_ring() < 0)
  {
    perror("Could not make trivial ring");
    exit(EXIT_FAILURE); 
  };

  for (p = 1; p < nprocs;  p++) 
  {
    if(add_new_node(&childpid) < 0)
    {
      perror("Could not add new node to ring");
      exit(EXIT_FAILURE); 
    };
    if (childpid) break; 
  };

/*              The computation begins here                               */
/**************************************************************************/
  pid_t wpid;            // To allow mother process to wait
  int status = 0;        // for the children to complete
  counter = 0;           // counter used to divide search-space

  if(p == 1)  //We are in the Mother process
  {
    fprintf(stderr, "\nProcess %d, start: %ld, max: %ld\n"\
    , p, counter, p*jobSize);
    send_key(message, message);
      while ((wpid = wait(&status)) > 0)    //The mother process waits for all
      {                                     //the children to finish
        get_key(message, message);        //Gets the key from previous process
                                        //prints key, and exits
        fprintf(stderr, "\n\n\nMother of all processes reporting in...\
          \nThe children were successful:\nThe full key is:   %s\n", message);
        return(0);
      }
  }
   
  /*******all processes*****************************************************/ 
  if(p==nprocs) //last process does its job + remainder
  {
    counter = (p-1)*jobSize;              //Partitions search space
    domainMax = (p*jobSize)+remainder;    //Assigns remainder to last process
  }
  else
  {
    counter = (p-1)*jobSize;              //Partitions search space
    domainMax = (p*jobSize);              
  }
 
  fprintf(stderr, "Process %d, start: %ld, max: %ld\n", p, counter, domainMax);

  if(counter <= domainMax) //Search assigned domain
  { 
    get_key(message, message); //Check if key has been sent
    for (counter = counter; counter < domainMax; counter++)
    {
      if(strlen(message) > 31)          //The key has been found
      {                                 //Pass key along and exit
        send_key(message, message);
        fprintf(stderr, "\nProcess: %d passing key immediately, exiting...", p);
        free (plaintext); //Free that memory
        return(0);
        
      }
      //OR the low bits of the key with the counter to get next test key
      unsigned long trialLowBits = keyLowBits | counter;
      //Unpack these bits into the end of the trial key array
      trialkey[25] = (unsigned char) (trialLowBits >> 48);
      trialkey[26] = (unsigned char) (trialLowBits >> 40);
      trialkey[27] = (unsigned char) (trialLowBits >> 32);
      trialkey[28] = (unsigned char) (trialLowBits >> 24);
      trialkey[29] = (unsigned char) (trialLowBits >> 16);
      trialkey[30] = (unsigned char) (trialLowBits >> 8);
      trialkey[31] = (unsigned char) (trialLowBits);

      //Set up the encryption device
      EVP_CIPHER_CTX *en = EVP_CIPHER_CTX_new ();
      EVP_CIPHER_CTX *de = EVP_CIPHER_CTX_new ();

      //Initialise the encryption device
      if (aes_init (trialkey, trial_key_length, en, de))
	    {
	      fprintf (stderr, "Couldn't initialize AES cipher\n");
	      return -1;
    	}

      // Test permutation of the key to see if we get the desired plain text
      plaintext = (char *) aes_decrypt (de,
			(unsigned char *) cipher_in,
			&cipher_length);

      // Cleanup Cipher Allocated memory
      EVP_CIPHER_CTX_cleanup (en);
      EVP_CIPHER_CTX_cleanup (de);
      EVP_CIPHER_CTX_free (en);
      EVP_CIPHER_CTX_free (de);


      //Key match checking
      //If key is found, pass value along ring and exit
      if (strncmp (plaintext, plain_in, plain_length) == 0)
    	{
	      int y;                        
	      for (y = 0; y < 32; y++)
	      {
          trialkey[y] = trialkey[y];
	      }
        strcpy(message, (const char * restrict)trialkey);    //copy key into buffer
        send_key(message, message);   //and pass it along
        fprintf(stderr, "\nProcess %d succesful, passing key along...", p);
        free (plaintext); //Free some memory
	      return(0);
	    }
    } 

    send_key(message, message);  //if didn't find the key
    free (plaintext);            //let next node know and close
    fprintf(stderr, "\nProcess %d sending key and closing...", p);
    return(0);
  }
}




