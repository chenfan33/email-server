#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h> 
#include <pthread.h>
#include <string.h>
#include <string>
#include <iostream>
#include <signal.h>
#include <vector> 
#include <fcntl.h>
#include<dirent.h>


using namespace std;

#define BUFFER_SIZE 1024
#define DIR_path ""   
char *DIR_NAME;
int PORT = 10000;
int THREAD_NUM = 100;
int VFLAG;
string ERR ("-ERR Unknown command\r\n");
string BYE ("+OK Goodbye!\r\n");
string GREET ("+OK Server ready (Author: Chen Fan / cfan3)\r\n");
string TERM ("-ERR Server shutting down\r\n");
char RETURN = '\r';
char SPACE  = ' ';
volatile int fds[100] = {0}; // signal handling
typedef struct thread_info {
    int client_fd;
    int id;
} th;

enum string_code {
    ECHO,
    QUIT,
    NONE
};

string_code hashh(std::string const& inString);
int read_argument(int argc, char *argv[]);//parse command line arguemnt
void *echo(void *vargp); // thread function
bool parseCommand(string command, int client_fd); // parse command from client
void greet(int client_fd);// greet client
void end(int client_fd, int id);//disconnect with client
void get_input(int client_fd);//read from client
void send_v(int client_fd, string message);//send message to given file descriptor
void intHandler(int dummy); // signal handling
void read_dir();
int main(int argc, char *argv[])
{

  if (!read_argument(argc, argv)){
    return (0);   
  }
  
  // create socket
  int server_fd = socket(PF_INET, SOCK_STREAM, 0);
  if (server_fd < 0){
    fprintf(stderr, "Socket Initialization Failed\n");
    exit(1);
  }

  signal(SIGINT, intHandler);

  // server address
  struct sockaddr_in server_addr;
  bzero((char *)&server_addr, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(PORT); // to be modified to new port
  server_addr.sin_addr.s_addr = INADDR_ANY;

  if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0){
    fprintf(stderr,"Socket bind Failed\n");
    exit(1);
  }

  if (listen(server_fd, THREAD_NUM) != 0){
    fprintf(stderr, "Listen Failed\n");
    exit(1);
  }
  else{
    printf("Server listening..\n");
  }

  int thread_num = 0;
  pthread_t threads[THREAD_NUM];

  while (thread_num < THREAD_NUM){
    struct sockaddr_in clientaddr;
    socklen_t clientaddrlen = sizeof(clientaddr);
    int client_fd = accept(server_fd, (struct sockaddr*)&clientaddr, &clientaddrlen);  
    fds[thread_num] = client_fd;// for signal handling
    // thread_info stores client fd and its index in fds
    thread_info *child;
    child = (thread_info *) malloc(sizeof(struct thread_info));
    child->client_fd = client_fd;
    child->id = thread_num;

    if (client_fd < 0){
      fprintf(stderr, "Socket Initialization Failed\n");
      exit(1);
    }

    if (VFLAG){
      fprintf(stderr, "[%d] New connection\n", client_fd);
    }
    
    pthread_t child_tid;
    threads[thread_num] = child_tid;

    if (pthread_create(&child_tid, NULL, echo, (void *)child) <  0){
      fprintf(stderr, "Socket Initialization Failed\n");
      exit(1);
    }
    thread_num ++;
  }

  for (int i = 0; i < THREAD_NUM; i ++){
    pthread_join(threads[i], NULL);
  }

  close(server_fd);
  return 0;
}

/**
 * parse command line arguments
 * return 0 if -a or invalid command
 * return 1 if valid
*/
int read_argument(int argc, char *argv[]){
  if (argc == 1){
    return 1;
  }
  int c;
  int index;
  opterr = 0;

  while ((c = getopt (argc, argv, "ap:v")) != -1){
    switch (c){
      case 'a':
        fprintf (stderr, "Chen Fan, cfan3\n");
        return 0;

      case 'p':
          PORT = atoi(optarg);
          if (PORT == 0){
            fprintf (stderr, "Please provide valid port number\n");
            return 0;
          }
        
        break;

      case 'v':
        VFLAG = 1;
        break;

      case '?':
        if (optopt == 'p')
          fprintf (stderr, "Option -%c requires an argument.\n", optopt);
        else if (isprint (optopt)){
          fprintf (stderr, "Unknown option `-%c'!\n", optopt);
        }
        else{
          fprintf (stderr, "Unknown option character `\\x%x',please use -a/-p/-v!!\n", optopt);
        }
        return 0;
      default:
        abort ();
      }
  }
  optind ++;
  for(; optind < argc; optind++){     
    printf("Non option arguments: %s\n", argv[optind]); 
    return 0;
  }
  return 1;
}








/**
 * Thread function to send and recv messages from client;
 * takes thread_info containing fd and index as input
*/
void *echo(void *vargp){
  thread_info *info = (thread_info *) vargp;
  int client_fd = info->client_fd;
  int id = info->id; // use to close fd in fds for signal handling
  greet(client_fd);
  get_input(client_fd);
  end(client_fd, id);
  return vargp;
}

/**
 * recv from client with client fd, and parse command
*/
void get_input(int client_fd){
	char buff[BUFFER_SIZE];
  int read_len;
  string command;// combining all small pieces
  bool quit = false;// whether receiving quit command

  // while still have input
  while(( read_len = recv(client_fd, buff, BUFFER_SIZE, 0)) > 0){
    if(read_len <= 0){
      fprintf(stderr,"Failed to read client\n");
      break;
    }

    if (read_len > BUFFER_SIZE){
      fprintf(stderr,"length exceeds buffer size\n");
      break;
    }
    
    if (VFLAG){
      string receive = buff;
      fprintf(stderr, "[%d]  C: %s\n", client_fd, receive.substr(0, read_len).c_str());
    }
    
    int length = command.length() + read_len;
    command += buff;
    command = command.substr(0, length);
    bzero(buff, read_len); // clean up the buff

    // if it contains a full line
    int pos = command.find("\r\n");
    // while command contains full line

    while (pos != string::npos){
      quit = parseCommand(command.substr(0, pos+2),  client_fd);
      if (!quit){
        if (command.length() > pos+2){
          command = command.substr(pos+2);
        }
        else{ command = ""; }
      }
      else{ break; }
      pos = command.find("\r\n");//keep looking for \r\n
    }
    if (quit){ break; }
  }

}


/**
 * Given a full line command with \r\n, return true if quit, else false
 * parse the command and send to client if ECHO
*/
bool parseCommand(string command, int client_fd){
    // shorter than required length to be a valid command
    if (command.length() < 6){
      send_v(client_fd, ERR.c_str());
      return false;
    }
    //store the token to parse
    auto first_token = command.substr(0, command.length()-2);
    
    // if command has space, then get substr before space as first token
    if (command.find(' ') != string::npos){
      int pos = command.find(' ');
      first_token = command.substr(0, pos);
    }

    string res;
    switch (hashh(first_token)){
      case ECHO:
        if (command.at(4) == SPACE || command.length() == 6){
          res = command.substr(5); // store substring after "ECHO"
          res = "+OK " + res;
          send_v(client_fd, res);
        }
        else{ send_v(client_fd, ERR.c_str());}
        return false;

      case QUIT:
        if (command.at(4) == SPACE || command.length() == 6){
          return true;
        }
        else{ send_v(client_fd, ERR.c_str());}
        return false;  

      case NONE:
        send_v(client_fd, ERR.c_str());
        return false;
      }
  return false;
}

/**
 * send greeting message to client fd
*/
void greet(int client_fd){
  send_v(client_fd, GREET);
}

/**
 * send googbye message to client fd
 * close fd, and set fds[id] to 0 for signal handling
*/
void end(int client_fd, int id){
  send_v(client_fd, BYE.c_str());
  printf("Connection closed: %d\n", client_fd);
  fds[id] = 0;
  close(client_fd);
}

/**
 * send message to client fd, print error if fails
*/
void send_v(int client_fd, string message){
  if (send(client_fd, message.c_str(), message.length(), 0) < 0){
    printf("Failed to write client\n");
    exit(0);
  }  
  if (VFLAG){
    fprintf(stderr, "[%d]  S: %s\n", client_fd, message.c_str());
  }
}

/**
 * signal handler, close all available fd in dfs
*/
void intHandler(int dummy) {
  for (int i = 0; i < 100; i++){
    if (fds[i]){
      // set fds[i] to nonblocking connection
      int status = fcntl(fds[i], F_SETFL, fcntl(fds[i], F_GETFL, 0) | O_NONBLOCK);
      send_v(fds[i], TERM);
      close(fds[i]);
    }
  }
  exit(0);
}
string_code hashh(std::string const& inString) {
    if (inString == "ECHO") return ECHO;
    if (inString == "QUIT") return QUIT;
    return NONE;
}