#include <stdlib.h>
#include <stdio.h>
#include <openssl/md5.h>
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
#include<dirent.h>
#include <map>
#include <iterator>
#include <sys/file.h>
#include <iostream>
#include <fstream>
#include <regex>

using namespace std;

#define BUFFER_SIZE 1024
char *DIR_NAME;
int PORT = 11000;
int THREAD_NUM = 100;
int VFLAG;
int BREAK = 0;
int INIS = 1;
int USER_ED = 2;
int AUTHORIZED = 3;
int TRANSC = 4;
int DELE_ED = 5;
int RSET_ED = 6;

string ERR ("-ERR Unknown command\r\n");
string BYE ("+OK Goodbye!\r\n");
string TERM ("-ERR Server shutting down\r\n");
string BAD_REQUEST ("-ERR bad sequence of command order\r\n");
char RETURN = '\r';
char SPACE  = ' ';
string PASSWORD ("cis505\r\n");
string CRLF = "\r\n";
volatile int fds[100] = {0}; // signal handling
regex pattern ("From <.*@[a-zA-Z0-9_]*> [a-zA-Z0-9_]{3} [a-zA-Z0-9_]{3} [\\[0-9]{2} [\\[0-9]{2}:[\\[0-9]{2}:[\\[0-9]{2} [\\[0-9]{4}");
map<string, pthread_mutex_t> muteces;

typedef struct thread_info {
    int client_fd;
    int id;
} th;

typedef struct email_info {
    int status; // 0 for deleted
    string content; // content
    string id; // UIDL
    int length;
    string header;
} ei;


typedef struct message_info {
    int status;
    string message;
} mi;
enum string_code {
    USER,
    PASS,
    STAT, 
    UIDL,
    RETR,
    DELE,
    QUIT, 
    LIST, 
    RSET,
    NOOP,
    NONE
};

string_code hashh(std::string const& inString);
int read_argument(int argc, char *argv[]);//parse command line arguemnt
void *echo(void *vargp); // thread function
message_info* parseCommand(string command, int client_fd, int status, map<int, email_info> maps); // parse command from client
void greet(int client_fd);// greet client
void end(int client_fd, int id);//disconnect with client
void get_input(int client_fd);//read from client
void send_v(int client_fd, string message);//send message to given file descriptor
void intHandler(int dummy); // signal handling
void read_dir(); // read input directory and store mutexes
char* lookup(); // look up for ip address
char * IP = lookup();
bool valid_user(string name); // check if user exists
map<int, email_info> read_mbox(string file, FILE *fp, int client_fd); 
map<int, email_info> parse_mbox(string mbox);

string computeDigest(string msg){
  /* The digest will be written to digestBuffer, which must be at least MD5_DIGEST_LENGTH bytes long */
  string result;
  const char* test = msg.c_str();
  unsigned char digestBuffer[16];
  MD5_CTX c;
  MD5_Init(&c);
  MD5_Update(&c, test, msg.length());
  MD5_Final(digestBuffer, &c);

  char buf[32];
  for (int i = 0; i < 16; i++){
      sprintf(buf, "%02x", digestBuffer[i]);
      result.append( buf );
  }
  return result;
}

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

  int thread_num = 0;
  pthread_t threads[THREAD_NUM];
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
  for ( auto& kv : muteces) {
    pthread_mutex_destroy(&kv.second);
  }
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
    fprintf(stderr,"Non option arguments: %s\n", argv[optind]); 
    return 0;
  }
  return 1;
}

/**
 * read directory and store mutex for each file
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
 * take string mbox as file name
 * return a map containing each emial information 
*/
map<int, email_info> parse_mbox(string mbox){
  map<int, email_info> maps;
  sregex_token_iterator iter(mbox.begin(), mbox.end(), pattern); // header 
  sregex_token_iterator split (mbox.begin(), mbox.end(), pattern, -1);//content
  sregex_token_iterator end;
  // skip the first content
  split ++;
  int index = 1;// email index
  for (;split != end; ++split, iter++){
    string content = *split;
    content = content.substr(2); // removing leading crlf

    string header = *iter;
    header += CRLF;//appending crlf since regex doesn't contain
    
    // for computing hex hashing
    string whole_msg = header + content;
    string id = computeDigest(whole_msg);
    
    email_info* info = new email_info{};
    info->content = content;
    info->status = 1;
    info->id = id;
    info->length = content.length();
    info->header = header;

    maps.insert(pair<int, email_info>(index, *info));
    index += 1;
  }
  return maps;
}

/**
 * read all contents in mbox, and return maps stored
 * if the file is lock, then use a dummy err_info to inform 
 * the function that calls it
*/
map<int, email_info> read_mbox(string file, FILE *fp, int client_fd){
  map<int, email_info> maps;

  pthread_mutex_t lock = muteces.find(file)->second;
  // dummy err_info to inform the function that calls it
  if (pthread_mutex_trylock(&lock) != 0){
    email_info* err_info = new email_info{};
    err_info->header = "locked";
    maps.insert(pair<int, email_info>(1, *err_info));
    return maps;
  }

  flock(fileno(fp), LOCK_EX);
  string mess;// all contents
  char ch;
  while ((ch = fgetc(fp)) != EOF){
    mess += ch;
  }
  maps = parse_mbox(mess);
  return maps;
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
 * parameters : file : key in the mutexes map(without directory)
 * things to do in update state
 * including unlock and fwrite to new temp file
*/
int update_state(string file, FILE *fp, map<int, email_info> mbox){
  FILE *newFile;
  string temp_name = DIR_NAME + "temp.mbox"s;
  string file_name = DIR_NAME + file; // file name including directory
  newFile = fopen(temp_name.c_str(), "w");
  
  for ( auto& kv : mbox) {
    // if current email not deleted
    if (kv.second.status != 0) {
      string header = kv.second.header;
      string content = kv.second.content;
      fwrite(header.c_str() , 1 , header.length(), newFile);
      fwrite(content.c_str() , 1 , content.length(), newFile);      
    }
  }  
  fclose(newFile);
  int res = rename(temp_name.c_str(), file_name.c_str());
  sleep(1);

  pthread_mutex_t lock = muteces.find(file)->second;
  pthread_mutex_unlock(&lock);
  flock(fileno(fp), LOCK_UN);
  fclose(fp);
  return 1;
}

/**
 * recv from client with client fd, and parse command
*/
void get_input(int client_fd){
	char buff[BUFFER_SIZE];
  int read_len;
  string command;// combining all small pieces
  message_info* mess = new message_info{};
  map<int, email_info> mbox_info;
  bool read_box = false;
  int status = 1;
  string user;
  FILE *fp;
  bool enterTransct = false;

  string mutex_file; // file name without directory, as the key to the mutexes map
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
      mess = parseCommand(command.substr(0, pos+2),  client_fd, status, mbox_info);
      status = mess->status;
      // if entered user
      if (status == USER_ED){
        user = mess->message;
      }

      // if authorized, enter transaction state
      if (status == AUTHORIZED){
        mutex_file = user + ".mbox";
        string file = DIR_NAME + mutex_file;
        fp = fopen(file.c_str(), "a+");
        if (fp == NULL){
          send_v(client_fd, "-ERR cannot access maildrop\r\n");
          status = INIS;
        }
        else{
            map<int, email_info> temp = read_mbox(mutex_file, fp, client_fd);
            std::map<int, email_info>::iterator it = temp.find(1);
            string res;
            if (it != temp.end() && it->second.header == "locked"){
              res = "-ERR maildrop already locked\r\n";
              status = INIS; // clear all information enter
              user = "";
            }
            else{
              res = "+OK maildrop locked and ready\r\n";
              mbox_info = temp;
              status = TRANSC;//enter transaction state
              enterTransct = true;
            }
            send_v(client_fd, res);
        }
      }
      
      if (status == DELE_ED){
        int index = stoi(mess->message);
        if (index != 0){
          mbox_info.find(index)->second.status = 0;
          string res = "+OK message "s + to_string(index) + " deleted\r\n";
          send_v(client_fd, res);
        }
        else{
          send_v(client_fd, ERR);
        }
        status = TRANSC;
      }

      if (status == RSET){
        for ( auto& kv : mbox_info) {
          // if current email not deleted
          if (kv.second.status == 0) {
            kv.second.status = 1;
          }
        }
        string res = "+OK maildrop has "s + to_string(mbox_info.size()) +" messages\r\n";
        send_v(client_fd, res);
        status = TRANSC;
      }
      
      // keep parsign rest command if not exit
      if (status != BREAK){
        if (command.length() > pos+2){
          command = command.substr(pos+2);
        }
        else{ command = ""; }
      }

      else{ break; }
      pos = command.find("\r\n");//keep looking for \r\n
    }
    if (status == BREAK){ 
      if (enterTransct){
        update_state(mutex_file, fp, mbox_info);
      }
      break; 
    }
  }
}

/**
 * Given a full line command with \r\n, return true if quit, else false
 * parse the command and send to client if ECHO
 * 0 - quit, 1 - authorization state, 2 - user state, 3 - authorized, 4 - transaction state, 5 - deleting, 6 - RSET
*/
message_info* parseCommand(string command, int client_fd, int status, map<int, email_info> maps){
    message_info *mess = new message_info{};
    mess->status = status;
    mess->message = "";
    char * ptr;
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

    switch (hashh(first_token)){
      case USER:{
        // if initial state or only HELO was sent
        if (status == INIS){
          if (command.at(4) == SPACE){
            string user = command.substr(5);
            user = user.substr(0, user.length()-2);
            if (valid_user(user)){
              res = "+OK "s+ user+ " is a valid mailbox\r\n";
              mess->status = USER_ED;
              mess->message = user;
              send_v(client_fd, res);
            }
            else{
              res = "-ERR never heard of mailbox name\r\n";
              send_v(client_fd, res);
            }
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
      }

      case  PASS:{
        // if initial state or only HELO was sent
        if (status == USER_ED){
          res = ERR;
          if (command.at(4) == SPACE){
            
            if (!command.substr(5).compare(PASSWORD)){
              mess->status = AUTHORIZED;
            }
            else{
              res = "-ERR invalid password\r\n";
              send_v(client_fd, res);
              mess->status = INIS; 
            }
          }
        }
        else{
          res = BAD_REQUEST;
          send_v(client_fd, res);
        }
        return mess;
      }

      case LIST:
        if (status == TRANSC){
          // if list all
          if (command.length() == 6){
            send_v(client_fd, "+OK scan listing follows\r\n");
            
            for ( auto& kv : maps) {
              // if current email not deleted
              if (kv.second.status != 0) {
                  string res = to_string(kv.first) + " "s + to_string(kv.second.length) + "\r\n";
                  send_v(client_fd, res);
              }
            }
            send_v(client_fd, ".\r\n");
          }
          else if (command.at(4) == SPACE && strtol(command.substr(5, command.length()-7).c_str(), &ptr, 10) != 0){
              int index = stoi(command.substr(5, command.length()-7));
              std::map<int, email_info>::iterator it = maps.find(index);
              if (it != maps.end() && it->second.status != 0){
                email_info kv = it->second;
                res = "+OK "+ to_string(it->first) + " "s + to_string(kv.length) + "\r\n";
                send_v(client_fd, res);
              }
              else{
                res = "-ERR no such message, only 2 messages in maildrop\r\n";
                send_v(client_fd, res);
              }
          }
          else{ 
            send_v(client_fd, ERR);
          }
        }

        else{
          res = BAD_REQUEST;
          send_v(client_fd, res);
        }

        return mess;

      case UIDL:
        if (status == TRANSC){
          // if list all
          if (command.length() == 6){
            send_v(client_fd, "+OK unique-id listing follows\r\n");
            
            for ( auto& kv : maps) {
              // if current email not deleted
              if (kv.second.status != 0) {
                  string res = to_string(kv.first) + " "s + kv.second.id + "\r\n";
                  send_v(client_fd, res);
              }
            }
            send_v(client_fd, ".\r\n");
          }
          else if (command.at(4) == SPACE && strtol(command.substr(5, command.length()-7).c_str(), &ptr, 10) != 0){
              int index = stoi(command.substr(5, command.length()-7));
              std::map<int, email_info>::iterator it = maps.find(index);
              if (it != maps.end() && it->second.status != 0){
                email_info kv = it->second;
                res = "+OK "+ to_string(it->first) + " "s + kv.id + "\r\n";
                send_v(client_fd, res);
              }
              else{
                res = "-ERR no such message, only 2 messages in maildrop\r\n";
                send_v(client_fd, res);
              }
          }
          else{ 
            send_v(client_fd, ERR);
          }
        }
        else{
          res = BAD_REQUEST;
          send_v(client_fd, res);
        }
        return mess;   
        
      case STAT:
        if(status == TRANSC){
          if (command.length() == 6){
            int num = 0; // number of emails
            int size = 0;// size of mailbox

            for ( auto& kv : maps) {
              // if current email not deleted
              if (kv.second.status != 0) {
                  num += 1;
                  size += kv.second.length;
              }
            }
            res = "+OK "s + to_string(num) + " "s + to_string(size) + "\r\n";
            send_v(client_fd, res);
          }
          else{
            res = "-ERR STAT shouldn't contains argument\r\n";
            send_v(client_fd, res);
          }
        }
        else{
          res = BAD_REQUEST;
          send_v(client_fd, res);
        }
        return mess;

      case RETR:
        if(status == TRANSC){
          if (command.at(4) == SPACE && strtol(command.substr(5, command.length()-7).c_str(), &ptr, 10) != 0){
            int index = stoi(command.substr(5, command.length()-7));
            std::map<int, email_info>::iterator it = maps.find(index);
            if (it != maps.end() && it->second.status != 0){
              res = "+OK message follows\r\n";
              send_v(client_fd, res);

              email_info kv = it->second;
              res = kv.content +".\r\n";
              send_v(client_fd, res);
            }
            else{
              res = "-ERR no such message, only 2 messages in maildrop\r\n";
              send_v(client_fd, res);
            }
          }
          else{
            send_v(client_fd, ERR);
          }
        }
        else{
          res = BAD_REQUEST;
          send_v(client_fd, res);
        }
        return mess;    


      case DELE:
        if(status == TRANSC){
          if (command.at(4) == SPACE && strtol(command.substr(5, command.length()-7).c_str(), &ptr, 10) != 0){
            string str_index = command.substr(5, command.length()-7);
            int index = stoi(str_index);
            std::map<int, email_info>::iterator it = maps.find(index);
            if (it != maps.end() && it->second.status != 0){
              mess->message = str_index;
              mess->status = DELE_ED;
            }
            else{
              res = "-ERR message "s + str_index + " already deleted\r\n";
              send_v(client_fd, res);
            }
          }
          else{
            send_v(client_fd, ERR);
          }
        }
        else{
          res = BAD_REQUEST;
          send_v(client_fd, res);
        }
        return mess;        


      case RSET:
        if (status == TRANSC){
          if (command.length() == 6){
            mess->status = RSET_ED;
          }
          else{ 
            send_v(client_fd, ERR);
          }
        }
        else{
          res = "-ERR unauthorized\r\n";
          send_v(client_fd, res);
        }
        return mess;

      case NOOP:
        if (status == TRANSC){
          if (command.length() == 6){
            res = "+OK\r\n";
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

      case QUIT:
        if (command.at(4) == SPACE || command.length() == 6){
          mess->status = BREAK;
        }
        else{ 
          send_v(client_fd, ERR);
        }
        return mess;

      case NONE:{
        res = "-ERR Not supported\r\n";
        send_v(client_fd, res);
      }
    }
  return mess;
}

/**
 * send greeting message to client fd
*/
void greet(int client_fd){
  string greet = "+OK POP3 ready "s+IP + "\r\n";

  send_v(client_fd, greet);
}
/**
 * used to look up ip address
*/
char* lookup(){
  char hostname[1024];
  hostname[1023] = '\0';
  gethostname(hostname, 1023);
  struct hostent *hp = gethostbyname(hostname);
  char *ip = inet_ntoa(*(struct in_addr*)(hp->h_addr_list[0]));
  return ip;
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

/**
 * send googbye message to client fd
 * close fd, and set fds[id] to 0 for signal handling
*/
void end(int client_fd, int id){
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
  exit(0);
}

string_code hashh(std::string const& inString) {
    if (inString == "USER") return USER;
    if (inString == "QUIT") return QUIT;
    if (inString == "DELE") return DELE;
    if (inString == "LIST") return LIST;
    if (inString == "RSET") return RSET;
    if (inString == "NOOP") return NOOP;
    if (inString == "RETR") return RETR;
    if (inString == "PASS") return PASS;
    if (inString == "STAT") return STAT;
    if (inString == "UIDL") return UIDL;
    return NONE;
}