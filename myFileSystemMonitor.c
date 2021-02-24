#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <strings.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/inotify.h>
#include <semaphore.h>
#include <pthread.h>
#include "libcli.h"
#include <unistd.h>
#include <poll.h>

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/time.h>
#include <memory.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <stdarg.h>

#define PORT 5000		//Netcat server port
#define BT_BUF_SIZE 1024
#define TELNET_PORT 12345	//Telnet listening port

// Global variables
char dir[100];
char ip[32];
char telnetBuffer[1024];
int telnetListen = 1;
int backTrace = 0;
sem_t semaphore;
int listenSkt;

int cmd_backtrace(struct cli_def *cli, char *command, char *argv[], int argc)
{
	backTrace = 1;
	sem_wait(&semaphore);
	cli_print(cli, telnetBuffer);
	return CLI_OK;
}

void *telnetBT()
{
    struct sockadd_in servaddr;
    struct cli_command *c;
    struct cli_def *cli;
    int on = 1;

    cli = cli_init();
    cli_set_hostname(cli, "myFileSystemMonitor");
    cli_set_banner(cli, "Welcome to CLI program");
    cli_allow_user(cli, "user", "111111");
    cli_register_command(cli, NULL, "backtrace", cmd_backtrace, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, NULL);

    listenSkt = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(listenSkt, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

}

int main(int argc, char *argv[]) 
{
    int option,fdHTML,fd,wd;
    pthread_t bt_thread;
    struct pollfd fds[2];
    sem_init(&semaphore, 0, 0);

    if(argc != 5)
    {
        printf("HELP: ./file -d [dir] -i [IP]\n");
        return 1;
    }

    if(pthread_create(&bt_thread, NULL, telnetBT, NULL) != 0)
    {
        perror("Thread error");
    }

    while((option = getopt(argc, argv, "d:i:")) != -1)
    {
        switch (option)
        {
        case 'd':
            strcpy(dir, optarg);
            printf("dir is: %s\n", dir);
            break;
        case 'i':
        {
            strcpy(ip, optarg);
            printf("ip is: %s\n", ip);
            break;
        }
        default:
            perror("Bad arguments\n");
            break;
        }
    }

    if(fdHTML = open("/var/www/html/index.html", O_WRONLY | O_TRUNC) == -1)
    {
        perror("Open html");
    }

    if(argc < 3)
    {
        printf("HELP: %s PATH [PATH ...]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    printf("To terminate press ENTER key\n");

    fd = inotify_init1(IN_NONBLOCK);
    if(fd == -1)
    {
        perror("inotify_initl error");
        exit(EXIT_FAILURE);
    }

    wd = inotify_add_watch(fd, dir, IN_OPEN | IN_CLOSE);
    if(wd == -1)
    {
        fprintf(stderr, "Cannot watch '%s'\n", dir);
        perror("inotify_add_watch failure");
        exit(EXIT_FAILURE);
    }

    //Polling preparation
    nfds_t nfds = 2;

    //Console input
    fds[0].fd = STDIN_FILENO;
    fds[0].events = POLLIN;

    //Inotify input
    fds[1].fd = fd;
    fds[1].events = POLLIN;

    // Wait for events and/or terminal input
    char *htmlHead = "<!DOCTYPE html><html><title>File Access Monitor</title><body>";
    write(fdHTML, htmlHead, strlen(htmlHead));
    printf("Listening for events\n");
}