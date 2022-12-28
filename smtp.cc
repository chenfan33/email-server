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
#include <netinet/in.h>
#include <sys/socket.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <dirent.h>
#include <map>
#include <iterator>
#include <sys/file.h>
#include <iostream>
#include <fstream>

using namespace std;

#define BUFFER_SIZE 1024
int PORT = 2500;
int THREAD_NUM = 100;
char *DIR_NAME;
char BACK = '>';
int VFLAG;
string ERR ("500 syntax error\r\n");
string TERM ("-ERR Server shutting down\r\n");
string BAD_REQUEST ("503 Bad sequence of commands\r\n");
string OK ("250 OK\r\n");
string FROM (" FROM:<");
string TO (" TO:<");
map<string, pthread_mutex_t> muteces;

int BREAK = 0;
int INIS = 1;
int HELO_ED = 2;
int MAIL_ED = 3;
int RCPT_ED = 4;
int DATA_ED = 5;

char SPACE  = ' ';
volatile int fds[100] = {0}; // signal handling
typedef struct thread_info {
    int client_fd;
    int id;
} th;

typedef struct message_info {
    int status; // after receiving one command
    string message;//message from one command(etc, string sender)
} mi;
enum string_code {
    ECHO,
    QUIT,
    HELO,
    MAIL,
    RCPT,
    DATA,
    RSET,
    NOOP,
    NONE
};
int read_argument(int argc, char *argv[]);//parse command line arguemnt
void *echo(void *vargp); // thread function
message_info* parseCommand(string command, int client_fd, bool first, int status); // parse command from client
void greet(int client_fd);// greet client
void end(int client_fd, int id);//disconnect with client
void get_input(int client_fd);//read from client
void send_v(int client_fd, string message);//send message to given file descriptor
void intHandler(int dummy); // signal handling
char* lookup();// loop up ip address
char * IP = lookup();
void read_dir(); // read input directory and store mutexes
bool valid_user(string name);//check if user exists
string_code hashit(std::string const& inString);//command code hashing
int send_email(string sender, vector<string> recpts, string message, char * date); 
bool has_value(string s);// if string is non-empty

int main(int argc, char *argv[])
{
  
  //returns 1 if valid argument
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

  int thread_num = 0;
  pthread_t threads[THREAD_NUM];

  //initialize all mutexes
  for ( auto& kv : muteces) {
    if (pthread_mutex_init(&kv.second, NULL) != 0) {
      fprintf(stderr,"Mutex initialization fails! \n");
      return 1;
    }
  }

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
    fprintf (stderr, "Please provide directory path\n");
    return 0;
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

  if (optind < argc){
    DIR_NAME = argv[optind];
    read_dir();
  }

  else {
    fprintf (stderr, "Please provide directory path\n");
    return 0;
  }
  optind ++;
  for(; optind < argc; optind++){     
    printf("Non option arguments: %s\n", argv[optind]); 
    return 0;
  }
  return 1;
}

/**
 * read directory stored in DIR_NAME
*/
void read_dir(){
  struct dirent *pDirent;
  DIR *pDir;
  pDir = opendir (DIR_NAME);
  if (pDir == NULL) {
    printf ("Cannot open directory '%s'\n", DIR_NAME);
    exit(0);
  }
  while ((pDirent = readdir(pDir)) != NULL) {
    pthread_mutex_t lock;
    muteces.insert(pair<string, pthread_mutex_t>(pDirent->d_name, lock));
  }
  closedir (pDir);
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
  int status = INIS;// initial state
  message_info* mess = new message_info{}; // store message and status after one command
  string sender; 
  vector<string> recpts;
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

    // if not quit or data command, parse the command string 
    if (status > BREAK && status < DATA_ED){
      int length = read_len + command.length();
      command += buff;
      command = command.substr(0, length);
      bzero(buff, read_len); // clean up the buff

      // if it contains a full line
      int pos = command.find("\r\n");
      // while command contains full line
      while (pos != string::npos){
        mess = parseCommand(command.substr(0, pos+2),  client_fd, true, status);
        status = mess->status;
        // if not exit state
        if (status != BREAK){
          // if command still has more to parse
          if (command.length() > pos+2){
            command = command.substr(pos+2);
          }
          else{ command = ""; }
          // if back to initial state
          if (status == HELO_ED){
            sender = "";
            recpts.clear();
          }
          // store sender if received mail from command
          else if (status == MAIL_ED){
            if (has_value(mess->message)){
              sender = mess->message;
            }
          }
          // store recpitents if received rcpt to command
          else if (status == RCPT_ED){
            if (mess->message.length() > 0){
              recpts.push_back(mess->message);
            }
          }
        }
        else if (status == BREAK) { break; }
        pos = command.find("\r\n");//keep looking for \r\n
      }
      if (status == BREAK){ break; }
    }
    if (status == BREAK){ break; }

    // if received DATA command, then keep adding recv
    else if(status == DATA_ED){
      int length = read_len + command.length();
      command += buff;
      command = command.substr(0, length);

      bzero(buff, read_len); 
      int pos = command.find("\r\n.\r\n");
      // once receive the end dot
      if (pos != string::npos){
        string res = "450 Requested action not taken: mailbox unavailable\r\n";
        time_t now = time(0);
        char* date = ctime(&now);
        string message = command.substr(0, pos+2);
        // if email sents successfully
        if (send_email(sender, recpts, message,date) == 1){
          res = OK;
          status = HELO_ED;
        }
        if (command.length() > pos+5){
            command = command.substr(pos+6);
        }
        else{ command = ""; }
        send_v(client_fd, res);        
      }
    }
  }
}

/**
 * fwrite email header and content to file
 * 0 - mailbox not found, no access, 1 - send successfully
*/
int send_email(string sender, vector<string> recpts, string message, char * date){
  FILE *fp;
  int res = 0;
  string header = "From <"s + sender + "> " + date;
  header = header.substr(0, header.length()-1) + "\r\n";
  for (int i = 0; i < recpts.size(); i++){
    string file = DIR_NAME + recpts[i] + ".mbox";
    string whole = header + message;
    fp = fopen(file.c_str(), "a");
    if(fp != NULL){
      string mutex_file = recpts[i] + ".mbox";
      pthread_mutex_t lock = muteces.find(mutex_file)->second;
      // if can obtain the lock
      if (pthread_mutex_trylock(&lock) == 0){
        flock(fileno(fp), LOCK_EX);

        fwrite(whole.c_str() , 1 , whole.length(), fp);
        flock(fileno(fp), LOCK_UN);
        
        pthread_mutex_unlock(&lock);
        res = 1;
      }
    }
    fclose(fp);
  }
  return res;
}

/**
 * string hashing to deal with command parsed
*/
string_code hashit(std::string const& inString) {
    if (inString == "ECHO") return ECHO;
    if (inString == "QUIT") return QUIT;
    if (inString == "HELO") return HELO;
    if (inString == "MAIL") return MAIL;
    if (inString == "RCPT") return RCPT;
    if (inString == "DATA") return DATA;
    if (inString == "RSET") return RSET;
    if (inString == "NOOP") return NOOP;
    return NONE;
}

/**
 * return true if nonempty else false
*/
bool has_value(string s){
  for(int i = 0; i < s.length(); i++){
    if(!isspace(s[i]))
      return true;
    }
  return false;
}

/**
 * Given a full line command with \r\n, return true if quit, else false
 * parse the command and send to client if ECHO
 * return value: 0 - quit/exit 1 - initial state, 2 - HELO, 3 - MAIL FROM, 4 - RCPT, 5 - DATA 
*/
message_info* parseCommand(string command, int client_fd, bool first, int status){
    message_info *mess = new message_info{};
    mess->status = status;
    mess->message = "";
    // shorter than required length to be a valid command
    if (command.length() < 6 || command.length() > 1024){
      send_v(client_fd, ERR);
      return mess;
    }

    //store the token to parse
    auto first_token = command.substr(0, command.length()-2);
    
    // if command has space, then get substr before space as first token
    if (command.find(' ') != string::npos){
      int pos = command.find(' ');
      first_token = command.substr(0, pos);
    }
    string res;
    switch (hashit(first_token)){
      case QUIT:
        if (status > INIS){
          if (command.at(4) == SPACE || command.length() == 6){
            mess->status = BREAK;
          }
          else{ 
            res = ERR;
            send_v(client_fd, res);
          }
        }
        else{
          res = BAD_REQUEST;
          send_v(client_fd, res);
        }
        return mess;

      case HELO:
        // if initial state or only HELO was sent
        if (status == INIS || status == HELO_ED){
          res = ERR;
          if (command.at(4) == SPACE){
            res = "501 Syntax error in parameters or arguments\r\n";
            if (has_value(command.substr(5))){
              res = "250 "s + IP + "\r\n"s;
              mess->status = HELO_ED;
            }
          }
          
        }
        else{
          res = BAD_REQUEST;
        }
        send_v(client_fd, res);
        return mess;

      case MAIL:
      // if HELO was sent
      if (status == HELO_ED){
        // response initialize to syntax error
        res = ERR;
        int pos = command.find("@");
        // if the syntax is valid, then change response to 250
        if (!command.substr(4, FROM.length()).compare(FROM) && pos != string::npos){
          int offset = 4 + FROM.length();
          string sender = command.substr(offset, pos-offset);
          string domain = command.substr(pos+1);
          int back_pos = domain.find(BACK); // check syntax
          if (back_pos != string::npos){
            domain = domain.substr(0, back_pos);
            if (has_value(sender) && has_value(domain)){
              res = OK;
              mess->status = MAIL_ED;
              mess->message = sender + "@"s + domain;

            }
            else{
              res = "501 Syntax error in parameters or arguments\r\n";
            }
          }
          else{
            res = "501 Syntax error in parameters or arguments\r\n";
          }
        }
      }
      else{
        res = BAD_REQUEST;
      }
      send_v(client_fd, res);
      return mess;

      case RCPT:
        // if get MAIL FROM already or RCPT
        if (status == MAIL_ED || status == RCPT_ED){
          res = ERR;
          if (!command.substr(4, TO.length()).compare(TO)){
            res = "501 Syntax error in parameters or arguments\r\n";
            int offset = 4 + TO.length();
            int back_pos = command.find(BACK);
            if (back_pos != string::npos){
              string rcpt = command.substr(offset, back_pos-offset);
              int pos = rcpt.find("@localhost");// extract user name
              
              if (pos != string::npos){
                rcpt = rcpt.substr(0, pos);

                if (valid_user(rcpt)){
                  res = OK;
                  mess->status = RCPT_ED;
                  mess->message = rcpt;
                }
                else{
                  res = "550 No such user here\r\n";
                }
              }
              else{
                res = "501 Syntax error in parameters or arguments\r\n";
              }
            }
            else{
              res = "501 Syntax error in parameters or arguments\r\n";
            }
          }
        }
        else{
          res = BAD_REQUEST;
        }
        send_v(client_fd, res);
        return mess;

      case DATA:
        // only if got RCPT
        if (status == RCPT_ED){
          if (command.length() == 6){
            res = "354 send the mail data, end with .\r\n";
            mess->status = DATA_ED;
          }
          else if (command.at(4) == SPACE){
            res = "501 Syntax error in parameters or arguments\r\n";
          }
          else{
            res = ERR;
          }
        }
        else{
          res = BAD_REQUEST;
        }
        send_v(client_fd, res);
        return mess;
      
      case NOOP:
        if (status > INIS){
          if (command.length() == 6){
            res = OK;
            send_v(client_fd, res);
          }
          else if (command.at(4) == SPACE){
            res = "501 Syntax error in parameters or arguments\r\n";
            send_v(client_fd, res);
          }
          else{
            res = ERR;
            send_v(client_fd, res);
          }
        }
        else{
          res = BAD_REQUEST;
          send_v(client_fd, res);
        }
        return mess;


      case RSET:
      // only after HELO
       if (status > INIS){
        if (command.length() == 6){
          mess->status = HELO_ED;
          res = OK;
        }
        else if (command.at(4) == SPACE){
          res = "501 Syntax error in parameters or arguments\r\n";
        }
        else{
          res = ERR;
        }
      }
      else{
        res = BAD_REQUEST;
      }
      send_v(client_fd, res);
      return mess;

      case NONE:
        send_v(client_fd, ERR);
      }
  mess->status = status;
  return mess;
}

/**
 * check if user exists in the directory
*/
bool valid_user(string name){
  string user = DIR_NAME + "/"s+ name+".mbox";
  FILE *fp;
  if (access(user.c_str(), F_OK) == 0) {
    return true;
  }
  return false;
}

char* lookup(){
  char hostname[1024];
  hostname[1023] = '\0';
  gethostname(hostname, 1023);
  struct hostent *hp = gethostbyname(hostname);
  char *ip = inet_ntoa(*(struct in_addr*)(hp->h_addr_list[0]));
  return ip;
}

/**
 * send greeting message to client fd
*/
void greet(int client_fd){
  string GREET = "220 localhost "s+ IP + " Service ready\r\n";
  send_v(client_fd, GREET);
}

/**
 * send googbye message to client fd
 * close fd, and set fds[id] to 0 for signal handling
*/
void end(int client_fd, int id){
  string BYE = "221 "s + IP + " Service closing transmission channel\r\n";
  send_v(client_fd, BYE.c_str());
  fds[id] = 0;
  close(client_fd);
}

/**
 * send message to client fd, print error if fails
*/
void send_v(int client_fd, string message){
  if (send(client_fd, message.c_str(), message.length(), 0) < 0){
    fprintf(stderr,"Failed to write client\n");
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

  for ( auto& kv : muteces) {
    pthread_mutex_destroy(&kv.second);
  }
  exit(0);
}
