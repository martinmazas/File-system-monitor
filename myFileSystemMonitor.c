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
#include <sys/stat.h>
#include <sys/wait.h>
#include <execinfo.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <time.h>
#include <stdbool.h>

#define PORT 5000 //Netcat server port
#define BT_BUF_SIZE 1024
#define TELNET_PORT 8000

#ifdef __GNUC__
#define UNUSED(d) d __attribute__((unused))
#else
#define UNUSED(d) d
#endif

typedef struct backtrace {
    char **trace;
    int trace_count;
    char is_active;
} backtrace_s;

// Global variables
char dir[100];
char ip[32];
char telnetBuffer[1024];
int telnetListen = 1;
sem_t semaphore;
int listenSkt;
backtrace_s* bt_p;
backtrace_s bt;
pthread_t thread_telnet;
void *backtrace_buffer[128];

// Send a message to netcat server when there is a notify
void sendToServer(char *time, char *access, char *name, FILE *fdHTML)
{
    int sock, nsent;
	char toSend[2048];
    struct sockaddr_in s = {0};
    s.sin_family = AF_INET;
    s.sin_port = htons(PORT);
    memset(toSend, 0, sizeof(toSend));

    if (inet_pton(AF_INET, ip, &s.sin_addr.s_addr) <= 0)
    {
        perror("\nInvalid address/Address not supported");
        exit(1);
    }

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (connect(sock, (struct sockaddr *)&s, sizeof(s)) < 0)
    {
        perror("connect");
        exit(1);
    }

    strcpy(toSend, "\nFILE ACCESSED: ");
	strcat(toSend, name);	
	strcat(toSend, "\nACCESS: ");
	strcat(toSend, access);
	strcat(toSend, "\nTIME OF ACCESS: ");
	strcat(toSend, time);
	strcat(toSend, "\n");
	strcat(toSend, "\0");
	
	if((nsent = send(sock, toSend, strlen(toSend), 0)) < 0)
	{
		perror("recv");
		exit(1);
	}

    close(sock);
    exit(0);
}

// Send notify to apache html page and calls to sendServer function
static void handle_events(int fd, int wd, FILE *fdHTML)
{
    char buffer[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
    const struct inotify_event *event;
    ssize_t len;
    char *ptr;
    pid_t newProcess;
    char timeBuffer[50];
    char operationBuffer[16];
    char nameBuffer[1024];

    // Loop while events can be read from inotify file descriptor

    for (;;)
    {
        //Read some events
        len = read(fd, buffer, sizeof(buffer));
        if (len == -1 && errno != EAGAIN)
        {
            perror("Read error");
            exit(EXIT_FAILURE);
        }

        if (len <= 0)
            break;

        //Loop over all events in the buffer
        for (ptr = buffer; ptr < buffer + len; ptr += sizeof(struct inotify_event) + event->len)
        {
            time_t currTime;
            struct tm *timeInfo;
            memset(nameBuffer, 0, 1024);
            memset(operationBuffer, 0, 16);
            event = (const struct inotify_event *)ptr;

            if (!(event->mask & IN_OPEN))
            {
                memset(timeBuffer, 0, sizeof(timeBuffer));
                currTime = time(NULL);
                timeInfo = localtime(&currTime);
                strftime(timeBuffer, 32, "%d-%B-%Y at %H:%M:%S", timeInfo);

                if (event->mask & IN_CLOSE_WRITE)
                    strcpy(operationBuffer, "WRITE");
                if (event->mask & IN_CLOSE_NOWRITE)
                    strcpy(operationBuffer, "READ");
            }

            //Name of watched directory
            if (wd == event->wd)
                strcat(nameBuffer, dir);

            //File name
            if (event->len)
            {
                strcat(nameBuffer, event->name);
            }

            newProcess = fork();
            if (newProcess == -1)
                perror("Fork error");

            if (newProcess == 0)
            {
                const char *emptyString = "";
                if ((strcmp(nameBuffer, emptyString) != 0) && (strcmp(operationBuffer, emptyString) != 0) && (strcmp(timeBuffer, emptyString) != 0))
                {

                    fprintf(fdHTML, "<h3>FILE ACCESSED: %s</h3>\n", nameBuffer);
                    fprintf(fdHTML, "<h3>ACCESS: %s</h3>\n", operationBuffer);
                    fprintf(fdHTML, "<h3>TIME OF ACCESS: %s</h3>\n", timeBuffer);
                    sendToServer(timeBuffer, operationBuffer, nameBuffer, fdHTML);
                }
            }
        }
    }
}

int cmd_backtrace(struct cli_def *cli, UNUSED(const char *command), UNUSED(char *argv[]), UNUSED(int argc)) 
{
    //Initialize backtrace collection
    bt_p->is_active = 1;
    cli_print(cli, "backtrace() returned %d addresses\n", bt_p->trace_count);
    //Prints all backtrace
    for (int j = 0; j < bt_p->trace_count; j++) {
        cli_print(cli, "%s\n", bt_p->trace[j]);
    }

    //Turns off semaphore
    sem_post(&semaphore);

    return CLI_OK;
}

void BackTrace()
{
    int nptrs = 0;
    char **strings;
    char counter[16];
    void *buffer[BT_BUF_SIZE];

    memset(buffer, 0, sizeof(buffer));
    memset(telnetBuffer, 0, sizeof(telnetBuffer));

    nptrs = backtrace(buffer, BT_BUF_SIZE);
    printf("BackTrace() returned %d addresses\n", nptrs);

    strings = backtrace_symbols(buffer, nptrs);
    if (strings == NULL)
    {
        perror("backtrace_symbols error");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < nptrs; i + 1)
    {
        sprintf(counter, "[%d]: ", i + 1);
        strcat(telnetBuffer, counter);
        strcat(telnetBuffer, strings[i]);
        strcat(telnetBuffer, "\n\0");
    }

    free(strings);
}

//Sets them as no-instrument-funcions as they are called inside instrument function
//Otherwise core dumps
void  __attribute__ ((no_instrument_function)) reset_backtrace () {
    free(bt.trace);
    bt.trace = (char**)malloc(0*sizeof(char*));
    bt.trace_count = 0;
    bt.is_active = 0;
}

//Sets them as no-instrument-funcions as they are called inside instrument function
//Otherwise core dumps

void  __attribute__ ((no_instrument_function)) collect_backtrace  (int trace_count, char** string) {
    bt.trace = (char**)realloc(bt.trace, (bt.trace_count + trace_count) * sizeof(char*));
    for (int h = 0; h < trace_count; h++) {
        bt.trace[bt.trace_count + h] = (char*)malloc(128*sizeof(char));
        strcpy(bt.trace[bt.trace_count + h], string[h]);
    }
    bt.trace_count += trace_count;
}

//Instrumentation
void  __attribute__ ((no_instrument_function))  __cyg_profile_func_enter (void *this_fn,
                                                                          void *call_site)
{
        if(bt.is_active == 1) {
            //Waits for libcli to finish print
            sem_wait(&semaphore);
            reset_backtrace();
        }


        if (!pthread_equal(thread_telnet, pthread_self())) {
            int trace_count = backtrace(backtrace_buffer, sizeof(telnetBuffer));
            char** string = backtrace_symbols(backtrace_buffer, trace_count);
            collect_backtrace(trace_count, string);
        }

}

void *telnetBT()
{
    struct sockaddr_in servaddr;
    struct cli_command *c;
    struct cli_def *cli;
    int on = 1, x;

    cli = cli_init();
    cli_set_hostname(cli, "myFileSystemMonitor");
    cli_set_banner(cli, "Welcome to CLI program");
    cli_allow_user(cli, "user", "111111");
    cli_register_command(cli, NULL, "backtrace", cmd_backtrace, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, NULL);
    listenSkt = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(listenSkt, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    // Listen on port
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(TELNET_PORT);
    if (bind(listenSkt, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("bind");
        exit(0);
    }

    if (listen(listenSkt, 50) < 0) {
        perror("listen");
        exit(0);
    }

    while (telnetListen && (x = accept(listenSkt, NULL, 0)))
    {
        // Pass the connection off to libcli
        cli_loop(cli, x);
        close(x);
    }

    // Free data structures
    cli_done(cli);
    pthread_exit(0);
}

int main(int argc, char *argv[])
{
    int option, fd, wd, poll_num;
    pthread_t bt_thread;
    struct pollfd fds[2];
    char buffer;

    bt_p = ((void *)&bt);
    sem_init(&semaphore, 0, 0);

    if (argc != 5)
    {
        printf("HELP: ./file -d [dir] -i [IP]\n");
        return 1;
    }

    if (pthread_create(&bt_thread, NULL, telnetBT, NULL) != 0)
    {
        perror("Thread error");
    }

    while ((option = getopt(argc, argv, "d:i:")) != -1)
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

    if (argc < 3)
    {
        printf("HELP: %s PATH [PATH ...]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    printf("To terminate press ENTER key\n");

    fd = inotify_init1(IN_NONBLOCK);
    if (fd == -1)
    {
        perror("inotify_initl error");
        exit(EXIT_FAILURE);
    }

    wd = inotify_add_watch(fd, dir, IN_OPEN | IN_CLOSE);
    if (wd == -1)
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

    printf("Listening for events\n");
    FILE *fdHTML = fopen("/var/www/html/index.html", "w");
    fprintf(fdHTML, "<head><title>My File System Monitor</title></head>");

    while (1)
    {
        poll_num = poll(fds, nfds, -1);
        if (poll_num == -1)
        {
            if (errno == EINTR)
                continue;
            perror("Poll error");
            exit(EXIT_FAILURE);
        }
        if (poll_num > 0)
        {
            if (fds[0].revents & POLLIN)
            {
                // Console input is available. Empty stdin and quit
                while (read(STDIN_FILENO, &buffer, 1) > 0 && buffer != '\n')
                    continue;
                break;
            }
        }

        if (fds[1].revents & POLLIN)
        {
            //Inotify events are available
            handle_events(fd, wd, fdHTML);
        }
    }

    printf("Events listening stopped");

    telnetListen = 0;
    close(listenSkt);
    fclose(fdHTML);
    close(fd);
    exit(EXIT_SUCCESS);
}