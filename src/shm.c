/*
    To Compile with appropiate Stack Trace and
    fullfill the requirements for the librt of tryolite
    $ gcc shm.c -lrt -g -rdynamic
*/

#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <execinfo.h>
#include <signal.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

void handler(int sig)
{
    void *array[10];
    size_t size;

    // get void*'s for all entries on the stack
    size = backtrace(array, 10);

    // print out all the frames to stderr
    fprintf(stderr, "Error: signal %d:\n", sig);
    printf("errno(%d): %s\n", errno, strerror(errno));
    backtrace_symbols_fd(array, size, STDERR_FILENO);
    exit(1);
}

int main()
{
    signal(SIGSEGV, handler); // install our handler

    printf("Initialising complex program\n");
    // int fd = open("/dev/shm/stage_two", 0, 0);
    // if (fd == -1)
    // {
    //     fprintf(stderr, "Error\n");
    //     printf("errno(%d): %s\n", errno, strerror(errno));
    // }
    // else
    // {
    //     printf("Success\n");
    // }
    while (1)
    {
        printf("Waiting to be hacked...\n");
        sleep(1);
    }
}