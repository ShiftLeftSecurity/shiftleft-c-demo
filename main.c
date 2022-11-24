/*
 * Insecure code examples
 */
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<unistd.h> // read(), write(), close()


/*
 * The following cases are using functions that are 
 * known to be dangerous, if used wrong. 
 */

#define BUF_SIZE 10

// Insecure use of strcpy
void insecure_strcpy(char *dst, char *src) {
  // bad strlen comparison
  if(strlen(dst) == 0 ) 
    return;
  // bad strlen comparison
  if(strlen(src) == 0) 
    return;
  // size of "dst" is not considered here
  strcpy(dst, src);
}

// Insecure use of "strcat" could result in 
// a buffer overflow
void insecure_strcat(char *dst, char *src) {
  // bad strlen comparison
  if(strlen(dst) == 0 ) 
    return;
  // bad strlen comparison
  if(strlen(src) == 0)  
    return;
  // size of "dst" is not considered here
  strcat(dst, src);
}

// Format string vulnerability usinf printf
int bad_printf_wrapper(char* format, char* value) {
  // bad strlen comparison
  if(strlen(format) == 0 &&
      strlen(value) == 0)
    return;
  printf(format, value);
}

// 
int insecure_sprintf(char* format, char* value) {
  char buffer [10];
  // bad strlen comparison
  if(strlen(format) == 0 &&
      strlen(value) == 0)
    return;
  return sprintf(buffer, format, strlen(value));
}

// Insecure use of "strncat" could result in 
// a buffer overflow
int insecure_strncat(char* src) {
  char buf[BUF_SIZE];
  // bad strlen comparison
  if(strlen(src) == 0) 
    return;
  // The calcualted size of the third parameter should be checked
  return strlen(strncat(buf, src, BUF_SIZE - strlen(src)));
}
// Insecure use of "strtok"
int insecure_strtok() {
  char *token;
  char *path = getenv("PATH");
  // the return value of strtok should be checked ":" could not be present
  token = strtok(path, ":");
  puts(token);
  return printf("PATH: %s\n", path); 
}
// Insecure usage of "gets"
int insecure_gets() {
  char str[10];
  // gets is not checking the size of the destination buffer
  gets(str);
  return printf("%s", str);
}

// Insecure usage of "getwd"
int insecure_getwd() {
  // Size of "dir" is too small
  char dir[12];
  // return value of "getwd" is not checked 
  getwd(dir);
  return printf("Working directory:%s\n",dir);
}

// Insecure usage of "getwd"
int insecure_scanf() {
  char name[12];
  // size of "name" is not considered here
  scanf("%s", name);
  return printf("Hello %s!\n", name);
}

/*
 * Signed integer overflow is undefined behavior. Shifts of signed values to the
 * left are very prone to overflow. 
 */
void bad_shifting1(int val) {
  val <<= 24;
}

void bad_shifting2(int val) {
  255 << val;
}

void bad_shifting3(int val) {
  val << val;
}

// A high level nesting could indicate bad coding style
// and (accidentally) introduce vulnerabilities
int func_with_nesting_level_of_3(int foo, int bar) {
  if (foo > 10) {
    if (bar > foo) {
      for(int i = 0; i < bar ;i++) {

      }
    }
  }
}

// Artificial example checking for 
// high number of loops in a function.
int high_number_of_loops () {
  for(int i = 0; i < 10; i++){  }
  for(int i = 0; i < 10; i++){  }
  for(int i = 0; i < 10; i++){  }
  for(int i = 0; i < 10; i++){  }
}

// Heap based buffer overflow 
int insecure_heap_handling(char* src, int asize) {
  char *ptr = malloc(asize);
  strncpy(ptr, src, asize);
  strlen(ptr);
}
// The return value of a read/recv/malloc call is not checked directly and
// the variable it has been assigned to (if any) does not
// occur in any check within the caller.
void unchecked_read() {
  // BUF_SIZE = 10
  char buf[BUF_SIZE];
  read(fd, buf, sizeof(buf));
}
// The return value of a read/recv/malloc call is not checked directly and
// the variable it has been assigned to (if any) does not
// occur in any check within the caller.
void checks_something_else() {
  char buf[BUF_SIZE];
  int nbytes = read(fd, buf, sizeof(buf));
  int foo = 10;
  if( foo != sizeof(buf)) {
    
  }
}
// When calling `send`, the return value must be checked to determine
// if the send operation was successful and how many bytes were transmitted.
void return_not_checked(int sockfd, void *buf, size_t len, int flags) {
    send(sockfd, buf, len, flags);
}

// For (buf, indices) pairs, determine those inside control structures (for, while, if ...)
// where any of the calls made outside of the body (block) are Inc operations. Determine
// the first argument of that Inc operation and check if they are used as indices for
// the write operation into the buffer.
int index_into_dst_array (char *dst, char *src, int offset) {
  int i;
  for(i = 0; i < strlen(src); i++) {
    dst[i + + j*8 + offset] = src[i];
  }
  return i;
}

// The set*uid system calls do not affect the groups a process belongs to. However, often
// there exists a group that is equivalent to a user (e.g. wheel or shadow groups are often
// equivalent to the root user).
// Group membership can only be changed by the root user.
// Changes to the user should therefore always be preceded by calls to set*gid and setgroups,
void setresuid_case() {
  // Minimal example
  setresuid();
}
void setresuid_groups() {
  // Minimal example
  setgroups();
  setresuid();
}

// The set*gid system calls do not affect the ancillary groups a process belongs to.
// Changes to the group membership should therefore always be preceded by a call to setgroups.
// Otherwise the process may still be a secondary member of the group it tries to disavow.
void setresgid_uid() {
  setresgid();
  setresuid();
}

// Heap based buffer overflow 
int insecure_memcpy(size_t len, char *src) {
  char *dst = malloc(len + 8);
  memcpy(dst, src, len + 7);
  return strlen(dst);
}

// The following function can cause a 
// time-of-check, time-of-use race condition
void insecure_race(char *path) {
    chmod(path, 0);
    rename(path, "/some/new/path");
}

// Insecure usage of "strlen".
// The return value of strlen is size_t 
// but the calling function returns int
int insecure_strlen(char *str) {
  if(str == NULL)
    return -1;
  else
    return strlen(str);
}

// A hihg number of parameters is 
// considered as bad coding style
int too_many_params(int a, int b, int c, int d, int e) {
  // no content because parameter check
}

// A high cyclomatic complexity 
// can increase the likelyhood 
// of security issues
int high_cyclomatic_complexity(int x) {
  while(true) {
    for(int i = 0; i < 10; i++) {
    }
    if(x<10) {}
  }
  if (x > 10) {
    for(int i = 0; i < 10; i++) {

     }
  }
}
// Functions that have too many lines should be refactored 
int func_with_many_lines(int x) {
  // Artificial basic example for too many lines
  x++;
  x++;
  x++;
  x++;
  x++;
  x++;
  x++;
  x++;
  x++;
  x++;
  x++;
  x++;
  x++;
  x++;
  x++;
  x++;
  x++;
  x++;
  return x;
}


/*
 * The following code is based on
 * https://github.com/hardik05/Damn_Vulnerable_C_Program
 */

struct Image
{
	char header[4];
	int width;
	int height;
	char data[10];
};

void stack_operation(){
	char buff[0x1000];
	while(1){
		stack_operation();
	}
}

int ProcessImage(char* filename){
	FILE *fp;
	struct Image img;

	fp = fopen(filename,"r");            //Statement   1

	if(fp == NULL)
	{
		printf("\nCan't open file or file doesn't exist.\r\n");
		exit(0);
	}


	while(fread(&img,sizeof(img),1,fp)>0)
	{
			printf("\n\tHeader\twidth\theight\tdata\t\r\n");

			printf("\n\t%s\t%d\t%d\t%s\r\n",img.header,img.width,img.height,img.data);


			//integer overflow 0x7FFFFFFF+1=0
			//0x7FFFFFFF+2 = 1
			//will cause very large/small memory allocation.
			int size1 = img.width + img.height;
			char* buff1=(char*)malloc(size1);

			//heap buffer overflow
			memcpy(buff1,img.data,sizeof(img.data));
			free(buff1);
			//double free	
			if (size1/2==0){
				free(buff1);
			}
			else{
				//use after free
				if(size1/3 == 0){
					buff1[0]='a';
				}
			}


			//integer underflow 0-1=-1
			//negative so will cause very large memory allocation
			int size2 = img.width - img.height+100;
			//printf("Size1:%d",size1);
			char* buff2=(char*)malloc(size2);

			//heap buffer overflow
			memcpy(buff2,img.data,sizeof(img.data));

			//divide by zero
			int size3= img.width/img.height;
			//printf("Size2:%d",size3);

			char buff3[10];
			char* buff4 =(char*)malloc(size3);
			memcpy(buff4,img.data,sizeof(img.data));

			//OOBR read bytes past stack/heap buffer
			char OOBR = buff3[size3];
			char OOBR_heap = buff4[size3];

			//OOBW write bytes past stack/heap buffer
			buff3[size3]='c';
			buff4[size3]='c';

			if(size3>10){
				//memory leak here
				buff4=0;
			}
			else{
				free(buff4);
			}
			int size4 = img.width * img.height;
			if(size4/2==0){
				//stack exhaustion here
				stack_operation();
			}
			else{
				//heap exhaustion here
				char *buff5;
				do{
				buff5 = (char*)malloc(size4);
				}while(buff5);
			}
			free(buff2);
	}
	fclose(fp);
	return 0;
}

struct Example_Struct
{
	char* ptr;
	int size;
} example_struct;

void free_field_reassigned(Example_Struct *example_struct, char* buf) {
  free(example_struct->ptr);
  if (example_struct->size == 0) {
    return;
  }
  example_struct->ptr = buf;
}
void not_free_field_reassigned(Example_Struct *example_struct, char* buf) {
  free(example_struct->ptr);
  if (example_struct->size == 0) {
    example_struct->ptr = NULL;
    return;
  }
  example_struct->ptr = buf;
}
void bad1(Example_Struct *example_struct) {
  void *x = NULL;
  example_struct->foo = x;
  free(x);
}
void *bad() {
  void *x = NULL;
  if (cond)
    free(x);
  return x;
}

void *false_positive() {
  void *x = NULL;
  free(x);
  if (cond)
    x = NULL;
  else
    x = NULL;
  return x;
}

/*
 * End of code from 
 * https://github.com/hardik05/Damn_Vulnerable_C_Program
 */

int main(int argc,char **argv) {
  char argumentInput[256];
  strcpy_bad(argumentInput, argv[1]);
  func_with_nesting_level_of_3(strlen(argv[1]), strlen(argv[2]))
}
