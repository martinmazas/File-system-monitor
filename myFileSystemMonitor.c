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
#define TELNET_PORT 12345 //Telnet listening port

// Global variables
char dir[100];
char ip[32];
char telnetBuffer[1024];
int telnetListen = 1;
int backTraceCmd = 0;
sem_t semaphore;
int listenSkt;

void sendToServer(char *time, char *access, char *name, FILE *fdHTML)
{
    int sock, nsent;
    char sendPacket[2048];
    memset(sendPacket, 0, sizeof(sendPacket));

    struct sockaddr_in s = {0};
    s.sin_family = AF_INET;
    s.sin_port = htons(PORT);

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

    fprintf(fdHTML, "<h3>FILE ACCESSED: %s</h3>\n",name);
    fprintf(fdHTML, "<h3>ACCESS: %s</h3>\n",access);
    fprintf(fdHTML, "<h3>TIME OF ACCESS: %s</h3>\n",time);
    // strcpy(sendPacket, "\nFILE ACCESSED: ");
    // strcat(sendPacket, name);
    // fprintf(fdHTML, sendPacket);
    // strcat(sendPacket, "\nACCESS: ");
    // strcat(sendPacket, access);
    // fprintf(fdHTML, sendPacket);
    // strcat(sendPacket, "\nTIME OF ACCESS: ");
    // strcat(sendPacket, time);
    // fprintf(fdHTML, sendPacket);
    // strcat(sendPacket, "\n");
    // strcat(sendPacket, "\0");


    if ((nsent = send(sock, sendPacket, strlen(sendPacket), 0)) < 0)
    {
        perror("recv");
        exit(1);
    }

    close(sock);
    exit(0);
}

static void handle_events(int fd, int wd, FILE *fdHTML)
{
    char buffer[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
    const struct inotify_event *event;
    ssize_t len;
    char *ptr;
    pid_t newProcess;
    char timeBuffer[32];
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
                // fprintf(fdHTML, timeBuffer);
                // write(fdHTML, timeBuffer, strlen(timeBuffer));
                // fprintf(fdHTML, " -> ");
                // write(fdHTML, " -> ", strlen(" -> "));

                if (event->mask & IN_CLOSE_WRITE)
                    strcpy(operationBuffer, "WRITE");
                if (event->mask & IN_CLOSE_NOWRITE)
                    strcpy(operationBuffer, "READ");
            }

            // fprintf(fdHTML, operationBuffer);
            // write(fdHTML, operationBuffer, strlen(operationBuffer));

            //Name of watched directory
            if (wd == event->wd)
                strcat(nameBuffer, dir);

            //File name
            if (event->len)
            {
                // char *fileAccess; 
                // char *fileName;
                // fileAccess = "FILE ACCESSED: ";
                // fileName  = event->name;
                // char *accessToPrint = (char *)malloc(1 + strlen(fileAccess) + strlen(fileName));
                // strcpy(accessToPrint, fileAccess);
                // strcat(accessToPrint, accessToPrint);
                // fprintf(fdHTML, event->name);
                // write(fdHTML, event->name, strlen(event->name));
                strcat(nameBuffer, event->name);
            }

            //Type of filesystem object
            // if (event->mask & IN_ISDIR)
            //     fprintf(fdHTML, " [dir]<br>");
            // write(fdHTML, " [dir]<br>", strlen(" [dir]<br>"));
            // else
            //     fprintf(fdHTML, " [file]<br>");
            // write(fdHTML, " [file]<br>", strlen(" [file]<br>"));

            newProcess = fork();
            if (newProcess == -1)
                perror("Fork error");

            if (newProcess == 0)
                sendToServer(timeBuffer, operationBuffer, nameBuffer, fdHTML);
        }
    }
}

int cmd_backtrace(struct cli_def *cli, char *command, char *argv[], int argc)
{
    backTraceCmd = 1;
    sem_wait(&semaphore);
    cli_print(cli, "%s", telnetBuffer);
    return CLI_OK;
}

void __attribute__((no_instrument_function)) __cyg_profile_func_enter(void *this_fn, void *call_site)
{
    if (backTraceCmd)
    {
        backTraceCmd = 0;
        BackTrace();
        sem_post(&semaphore);
    }
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
    printf("backtrace() returned %d addresses\n", nptrs);

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

void *telnetBT()
{
    struct sockaddr_in servaddr;
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
    int option, fd, wd, poll_num;
    pthread_t bt_thread;
    struct pollfd fds[2];
    char buffer;

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
    FILE *fdHTML = fopen("/var/www/html/index.html", "w");
    fprintf(fdHTML, "<head><title>My File System Monitor</title></head>");
    fprintf(fdHTML, "<h1 style='color:red;'>Welcome to directory watcher</h1>");
    // if(fdHTML = open("/var/www/html/index.html", O_WRONLY | O_TRUNC) == -1)
    // {
    //     perror("Open html");
    // }

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

    // Wait for events and/or terminal input

    // char *htmlHead = "<!DOCTYPE html><html><title>File Access Monitor</title><body>";
    // write(fdHTML, htmlHead, strlen(htmlHead));
    printf("Listening for events\n");

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

    printf("Events listenint stopped");

    telnetListen = 0;
    close(listenSkt);
    // write(fdHTML, "</html></body>", strlen("</html></body>"));
    close(fdHTML);
    close(fd);
    exit(EXIT_SUCCESS);
}