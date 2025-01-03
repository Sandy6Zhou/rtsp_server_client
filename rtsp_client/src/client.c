#include <sys/types.h>
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <semaphore.h>
#include <mqueue.h>
#include "rtsp_type.h"
#include "rtsp_client.h"
#include "tpool.h"

static void help(int status);
static void help(int status)
{
    printf("Usage: rpsp_client -u rtsp://url\n\n");
    printf("  -u, --url=rtsp://      rtsp address\n");
	printf("  -h, --help             print this help\n");
	printf("\n");
	exit(status);
}

static int32_t quitflag = 0x00;
static void signal_handler(int signo)
{
    printf("catch signal NO. %d\n", signo);
    quitflag = 0x01;
    return;
    exit(1);
}

static void signal_init()
{
    signal(SIGINT, signal_handler);
    signal(SIGHUP, signal_handler);
    signal(SIGQUIT, signal_handler);
    return;
}

// mqd_t mqd;
int32_t main(int argc, char **argv)
{
    sleep(1);
    signal_init();
    // uint32_t length = 1920*1080;
    // mqd = mq_open("/nvr_buffer",O_RDWR | O_CREAT,S_IWUSR|S_IRUSR,NULL);
    int32_t opt;
    char *url = NULL;
    static const struct option long_opts[] = {
                            { "url", required_argument, NULL, 'u'},
                            { "help", no_argument, NULL, 'h'},
                            { NULL, 0, NULL, 0 }
                        };

    while ((opt = getopt_long(argc, argv, "u:h",
                       long_opts, NULL)) != -1) {
        switch (opt) {
            case 'u':
                if (NULL == (url  = strdup(optarg))){
                    fprintf(stderr, "Error : Url Address Equal Null.\n");
                    return 0x00;
                }
                break;
            case 'h':
                help(EXIT_SUCCESS);
                break;
            default:
                break;
        }
    }

    RtspClientSession *cses = InitRtspClientSession();
    if ((NULL == cses) || (False == ParseRtspUrl(url, &(cses->sess)))){
        fprintf(stderr, "Error : Invalid Url Address.\n");
        return 0x00;
    }

    pthread_t rtspid = RtspCreateThread(RtspEventLoop, (void *)cses);
    if (rtspid < 0x00){
        fprintf(stderr, "RtspCreateThread Error!\n");
        return 0x00;
    }

    do{
        if (0x01 == quitflag){
            SetRtspClientSessionQuit(cses);
            pthread_join(rtspid, NULL);
            break;
        }
        sleep(1);
    }while(1);

    printf("RTSP Event Loop stopped, waiting 5 seconds...\n");
    DeleteRtspClientSession(cses);
    return 0x00;
}

