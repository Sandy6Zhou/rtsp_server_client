#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "rtsp_type.h"
#include "utils.h"
#include "rtsp.h"
#include "rtsp_common.h"
#include "rtsp_response.h"
#include "net.h"

// 简单的Base64编码函数
char *base64_encode(const unsigned char *data, size_t input_length) {
    const char encoding_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t output_length = 4 * ((input_length + 2) / 3); // 向上舍入
    char *encoded_data = malloc(output_length + 1);
    size_t i, j;
    
    for (i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? data[i++] : 0;
        uint32_t octet_b = i < input_length ? data[i++] : 0;
        uint32_t octet_c = i < input_length ? data[i++] : 0;
        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;
        
        encoded_data[j++] = encoding_table[(triple >> 18) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 12) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 6) & 0x3F];
        encoded_data[j++] = encoding_table[triple & 0x3F];
    }

    // 处理填充
    for (size_t k = 0; k < (output_length % 4); k++) {
        encoded_data[output_length - 1 - k] = '=';
    }
    
    encoded_data[output_length] = '\0';
    return encoded_data;
}

static int32_t RtspSendKeepAliveCommand(RtspSession *sess);
static int32_t RtspSendOptionsCommand(RtspSession *sess)
{
    int32_t size = sizeof(sess->buffctrl.buffer);
    int32_t sock = sess->sockfd;
    char *buf = sess->buffctrl.buffer;

    memset(buf, '\0', size);
    int32_t num = snprintf(buf, size, CMD_OPTIONS, sess->url, sess->cseq);
    if (num < 0x00){
        fprintf(stderr, "%s : snprintf error!\n", __func__);
        return False;
    }

    num = TcpSendData(sock, buf, (uint32_t)num);
    if (num < 0){
        fprintf(stderr, "%s : Send Error\n", __func__);
        return False;
    }

    return True;
}

int32_t RtspOptionsCommand(RtspSession *sess)
{
    int32_t num;
    int32_t size = sizeof(sess->buffctrl.buffer);
    char *buf = sess->buffctrl.buffer;
    int32_t sock = sess->sockfd;
#ifdef RTSP_DEBUG
    printf("++++++++++++++++++  OPTIONS: command  +++++++++++++++++++++\n");
#endif
    if (False == RtspSendOptionsCommand(sess))
        return False;
#ifdef RTSP_DEBUG
    printf("OPTIONS Request: %s\n", buf);
#endif
    memset(buf, '\0', size);
    num = RtspReceiveResponse(sock, &sess->buffctrl);
    if (num <= 0) {
        printf("Error: Server did not respond properly, closing...");
        return False;
    }

#ifdef RTSP_DEBUG
    printf("\nOptions Reply: %s\n", buf);
#endif
    if (ST_OK != RtspCheckResponseStatus(buf))
        return False;


    ParseOptionsPublic(buf, num, sess);
    sess->status = RTSP_DESCRIBE;
    return True;
}

static int32_t RtspSendDescribeCommand(RtspSession *sess, char *buf, uint32_t size)
{
    int32_t sock = sess->sockfd;
    int32_t num;
    memset(buf, '\0', size);
    if(sess->auth_struct.auth_mode == NONE) {
        num = snprintf(buf, size, CMD_DESCRIBE, sess->url, sess->cseq);

        if (num < 0x00){
            fprintf(stderr, "%s : snprintf error!\n", __func__);
            return False;
        }
    }else if(sess->auth_struct.auth_mode == AUTH_BASIC) {
        char credentials[256]={0};
        snprintf(credentials, sizeof(credentials), "%s:%s", sess->username, sess->password);
        char *encoded = base64_encode((unsigned char *)credentials, strlen(credentials));
        strncpy(sess->auth_struct.auth_basic, encoded, sizeof(sess->auth_struct.auth_basic));
        free(encoded);

        num = snprintf(buf, size, CMD_DESCRIBE_AUTH_BASIC, sess->url, sess->cseq, sess->auth_struct.auth_basic);
        if (num < 0x00){
            fprintf(stderr, "%s : snprintf error!\n", __func__);
            return False;
        }
    }else if(sess->auth_struct.auth_mode == AUTH_DIGEST) {
        MakeDigestCodeResponse(sess,"DESCRIBE");
        num = snprintf(buf, size, CMD_DESCRIBE_AUTH_DIGEST, sess->url, sess->cseq,sess->username,\
        sess->auth_struct.realm,sess->auth_struct.nonce,sess->url,sess->auth_struct.auth_response);
        if (num < 0x00){
            fprintf(stderr, "%s : snprintf error!\n", __func__);
            return False;
        }
    }

    num = TcpSendData(sock, buf, (uint32_t)num);
    if (num < 0){
        fprintf(stderr, "%s : Send Error\n", __func__);
        return False;
    }
    
    return True;
}

int32_t RtspDescribeCommand(RtspSession *sess)
{
    int32_t num;
    int32_t size = sizeof(sess->buffctrl.buffer);
    char *buf = sess->buffctrl.buffer;
    int32_t sock = sess->sockfd;

#ifdef RTSP_DEBUG
    printf("++++++++++++++++++++++  DESCRIBE: command  +++++++++++++++++++++++++++\n");
#endif

    if (False == RtspSendDescribeCommand(sess, buf, size))
        return False;

#ifdef RTSP_DEBUG
    printf("DESCRIBE Request: %s\n", buf);
#endif

    memset(buf, '\0', size);
    num = RtspReceiveResponse(sock, &sess->buffctrl);
    if (num <= 0) {
        printf("Error: Server did not respond properly, closing...");
        return False;
    }

#ifdef RTSP_DEBUG
    printf("\nDescribe Reply: %s\n", buf);
#endif
    switch (RtspCheckResponseStatus(buf))
    {
        case ST_OK:
        {
        ParseSdpProto(buf, num, sess);
        sess->status = RTSP_SETUP;
        return True;
        }
        case ST_UNAUTHORIZED:
        {
            sess->status = RTSP_DESCRIBE;
            ParseUnauthorizedMess(buf,num,sess);
            return True;
        }
        default:
        {

        }
    }
    return False;
}

static int32_t RtspSendSetupCommand(RtspSession *sess)
{
    int32_t size = sizeof(sess->buffctrl.buffer);
    int32_t num = 0x00;
    int32_t sock = sess->sockfd;
    char *buf = sess->buffctrl.buffer;
    char url[256];

    memset(buf, '\0', size);
    memset(url, '\0', sizeof(url));
    if (NULL == strstr(sess->vmedia.control, PROTOCOL_PREFIX)){
        int32_t len = strlen(sess->url);
        strncpy(url, sess->url, len);
        url[len] = '/';
        url[len+1] = '\0';
    }
    strncat(url, sess->vmedia.control, strlen(sess->vmedia.control));
#ifdef RTSP_DEBUG
    printf("SETUP URL: %s\n", url);
#endif
    if(sess->auth_struct.auth_mode == NONE) {
        if (RTP_AVP_TCP == sess->trans){
            num = snprintf(buf, size, CMD_TCP_SETUP, url, sess->cseq);
        }else if (RTP_AVP_UDP == sess->trans){
            num = snprintf(buf, size, CMD_UDP_SETUP, url, sess->cseq, 30000, 30001);
        }
        if (num < 0x00){
            fprintf(stderr, "%s : snprintf error!\n", __func__);
            return False;
        }
    }else if(sess->auth_struct.auth_mode == AUTH_BASIC) {
        if (RTP_AVP_TCP == sess->trans){
            num = snprintf(buf, size, CMD_TCP_SETUP_AUTH_BASIC, url, sess->cseq, sess->auth_struct.auth_basic);
        }else if (RTP_AVP_UDP == sess->trans){
            num = snprintf(buf, size, CMD_UDP_SETUP_AUTH_BASIC, url, sess->cseq, sess->auth_struct.auth_basic, 30000, 30001);
        }
        if (num < 0x00){
            fprintf(stderr, "%s : snprintf error!\n", __func__);
            return False;
        }
    }else if(sess->auth_struct.auth_mode == AUTH_DIGEST) {
        MakeDigestCodeResponse(sess,"SETUP");
        if (RTP_AVP_TCP == sess->trans){
            num = snprintf(buf, size, CMD_TCP_SETUP_AUTH_DIGEST, url, sess->cseq,sess->username,\
            sess->auth_struct.realm,sess->auth_struct.nonce,sess->url,sess->auth_struct.auth_response);
        }else if (RTP_AVP_UDP == sess->trans){
            num = snprintf(buf, size, CMD_UDP_SETUP_AUTH_DIGEST, url, sess->cseq,sess->username,\
            sess->auth_struct.realm,sess->auth_struct.nonce,sess->url,sess->auth_struct.auth_response, 30000, 30001);
        }
        if (num < 0x00){
            fprintf(stderr, "%s : snprintf error!\n", __func__);
            return False;
        }
    }


    num = TcpSendData(sock, buf, (uint32_t)num);
    if (num < 0){
        fprintf(stderr, "%s : Send Error\n", __func__);
        return False;
    }
    return True;
}

int32_t RtspSetupCommand(RtspSession *sess)
{
    int32_t num;
    int32_t size = sizeof(sess->buffctrl.buffer);
    char *buf = sess->buffctrl.buffer;
    int32_t sock = sess->sockfd;

#ifdef RTSP_DEBUG
    printf("++++++++++++++++++++  SETUP: command  +++++++++++++++++++++++++\n");
#endif


    if (False == RtspSendSetupCommand(sess))
        return False;

#ifdef RTSP_DEBUG
    printf("SETUP Request: %s\n", buf);
#endif
    memset(buf, '\0', size);
    num = RtspReceiveResponse(sock, &sess->buffctrl);
    if (num <= 0) {
        fprintf(stderr, "Error: Server did not respond properly, closing...");
        return False;
    }

#ifdef RTSP_DEBUG
    printf("SETUP Reply: %s\n", buf);
#endif
    switch (RtspCheckResponseStatus(buf))
    {
        case ST_OK:
        {
            if (RTP_AVP_UDP == sess->trans){
                ParseUdpPort(buf, num, sess);
            }else{
                ParseInterleaved(buf, num, sess);
            }
            ParseSessionID(buf, num, sess);
            sess->packetization = 1;
            sess->status = RTSP_PLAY;
            return True;
        }
        case ST_UNAUTHORIZED:
        {
            sess->status = RTSP_SETUP;
            ParseUnauthorizedMess(buf,num,sess);
            return True;
        }
        default:
        {

        }
    }
    return False;
}

static int32_t RtspSendPlayCommand(RtspSession *sess)
{
    int32_t size = sizeof(sess->buffctrl.buffer);
    int32_t sock = sess->sockfd;
    char *buf = sess->buffctrl.buffer;
    int32_t num = 0;
    memset(buf, '\0', size);

    if(sess->auth_struct.auth_mode == NONE) {
        num = snprintf(buf, size, CMD_PLAY, sess->url, sess->cseq, sess->sessid);
        if (num < 0x00){
            fprintf(stderr, "%s : snprintf error!\n", __func__);
            return False;
        }
    }else if(sess->auth_struct.auth_mode == AUTH_BASIC) {
        num = snprintf(buf, size, CMD_PLAY_AUTH_BASIC, sess->url, sess->cseq, sess->auth_struct.auth_basic, sess->sessid);
        if (num < 0x00){
            fprintf(stderr, "%s : snprintf error!\n", __func__);
            return False;
        }
    }else if(sess->auth_struct.auth_mode == AUTH_DIGEST) {
        MakeDigestCodeResponse(sess,"PLAY");
        num = snprintf(buf, size, CMD_PLAY_AUTH_DIGEST, sess->url, sess->cseq,sess->username,\
        sess->auth_struct.realm,sess->auth_struct.nonce,sess->url,sess->auth_struct.auth_response, sess->sessid);
        if (num < 0x00){
            fprintf(stderr, "%s : snprintf error!\n", __func__);
            return False;
        }
    }

    num = TcpSendData(sock, buf, (uint32_t)num);
    if (num < 0){
        fprintf(stderr, "%s : Send Error\n", __func__);
        return False;
    }

    return True;
}

int32_t RtspPlayCommand(RtspSession *sess)
{
    int32_t num;
    int32_t size = sizeof(sess->buffctrl.buffer);
    int32_t sock = sess->sockfd;
    char *buf = sess->buffctrl.buffer;

#ifdef RTSP_DEBUG
    printf("+++++++++++++++++++  PLAY: command  ++++++++++++++++++++++++++\n");
#endif
    if (False == RtspSendPlayCommand(sess))
        return False;

#ifdef RTSP_DEBUG
    printf("PLAY Request: %s\n", buf);
#endif

    memset(buf, '\0', size);
    num = RtspReceiveResponse(sock, &sess->buffctrl);
    if (num <= 0) {
        fprintf(stderr, "Error: Server did not respond properly, closing...");
        return False;
    }

#ifdef RTSP_DEBUG
    printf("PLAY Reply: %s\n", buf);
#endif
    switch (RtspCheckResponseStatus(buf))
    {
        case ST_OK:
        {
            ParseTimeout(buf, num, sess);
            gettimeofday(&sess->last_cmd_time, NULL);
            sess->status = RTSP_KEEPALIVE;
            RtspSendKeepAliveCommand(sess);
            return True;
        }
        case ST_UNAUTHORIZED:
        {
            sess->status = RTSP_PLAY;
            ParseUnauthorizedMess(buf,num,sess);
            return True;
        }
        default:
        {

        }
    }
    return False;
}

static int32_t RtspSendKeepAliveCommand(RtspSession *sess)
{
    // if (True == RtspCommandIsSupported(RTSP_GET_PARAMETER, sess)){
    //     RtspGetParameterCommand(sess);
    // }else{
    //     RtspOptionsCommand(sess);
    // }

    return True;
}

int32_t RtspKeepAliveCommand(RtspSession *sess)
{
    struct timeval now;
    gettimeofday(&now, NULL);

    if (now.tv_sec - sess->last_cmd_time.tv_sec > sess->timeout-5){
#ifdef RTSP_DEBUG
    printf("+++++++++++++++++++  Keep alive: command  ++++++++++++++++++++++++++\n");
#endif
        RtspSendKeepAliveCommand(sess);
        sess->last_cmd_time = now;
    }

    return True;
}

static int32_t RtspSendGetParameterCommand(RtspSession *sess)
{
    int32_t size = sizeof(sess->buffctrl.buffer);
    int32_t sock = sess->sockfd;
    char *buf = sess->buffctrl.buffer;
    int32_t num = 0;
    memset(buf, '\0', size);

    if(sess->auth_struct.auth_mode == NONE) {
        num = snprintf(buf, size, CMD_GET_PARAMETER, sess->url, sess->cseq, sess->sessid);
        if (num < 0x00){
            fprintf(stderr, "%s : snprintf error!\n", __func__);
            return False;
        }
    }else if(sess->auth_struct.auth_mode == AUTH_BASIC) {
        num = snprintf(buf, size, CMD_GET_PARAMETER_AUTH_BASIC, sess->url, sess->cseq, sess->auth_struct.auth_basic, sess->sessid);
        if (num < 0x00){
            fprintf(stderr, "%s : snprintf error!\n", __func__);
            return False;
        }
    }else if(sess->auth_struct.auth_mode == AUTH_DIGEST) {
        MakeDigestCodeResponse(sess,"GET_PARAMETER");
        num = snprintf(buf, size, CMD_GET_PARAMETER_AUTH_DIGEST, sess->url, sess->cseq,sess->username,\
        sess->auth_struct.realm,sess->auth_struct.nonce,sess->url,sess->auth_struct.auth_response, sess->sessid);
        if (num < 0x00){
            fprintf(stderr, "%s : snprintf error!\n", __func__);
            return False;
        }
    }

    num = TcpSendData(sock, buf, (uint32_t)num);
    if (num < 0){
        fprintf(stderr, "%s : Send Error\n", __func__);
        return False;
    }

    return True;
}

int32_t RtspGetParameterCommand(RtspSession *sess)
{
    int32_t num;
    int32_t size = sizeof(sess->buffctrl.buffer);
    int32_t sock = sess->sockfd;
    char *buf = sess->buffctrl.buffer;

#ifdef RTSP_DEBUG
    printf("+++++++++++++++++++  Get Parameter: command  ++++++++++++++++++++++++++\n");
#endif
    if (False == RtspSendGetParameterCommand(sess))
        return False;

#ifdef RTSP_DEBUG
    printf("GET_PARAMETER Request: %s\n", buf);
#endif
    memset(buf, '\0', size);
    num = RtspReceiveResponse(sock, &sess->buffctrl);
    if (num <= 0) {
        fprintf(stderr, "Error: Server did not respond properly, closing...");
        return False;
    }


#ifdef RTSP_DEBUG
    printf("GET PARAMETER Reply: %s\n", buf);
#endif
    switch (RtspCheckResponseStatus(buf))
    {
        case ST_OK:
        {
            return True;
        }
        case ST_UNAUTHORIZED:
        {
            sess->status = RTSP_GET_PARAMETER;
            ParseUnauthorizedMess(buf,num,sess);
            return True;
        }
        default:
        {

        }
    }
    return False;
}


static int32_t RtspSendTeardownCommand(RtspSession *sess)
{
    int32_t size = sizeof(sess->buffctrl.buffer);
    int32_t sock = sess->sockfd;
    char *buf = sess->buffctrl.buffer;
    int32_t num = 0;
    memset(buf, '\0', size);

    if(sess->auth_struct.auth_mode == NONE) {
        num = snprintf(buf, size, CMD_TEARDOWN, sess->url, sess->cseq, sess->sessid);
        if (num < 0x00){
            fprintf(stderr, "%s : snprintf error!\n", __func__);
            return False;
        }
    }else if(sess->auth_struct.auth_mode == AUTH_BASIC) {
        num = snprintf(buf, size, CMD_TEARDOWN_AUTH_BASIC, sess->url, sess->cseq, sess->auth_struct.auth_basic, sess->sessid);
        if (num < 0x00){
            fprintf(stderr, "%s : snprintf error!\n", __func__);
            return False;
        }
    }else if(sess->auth_struct.auth_mode == AUTH_DIGEST) {
        MakeDigestCodeResponse(sess,"TEARDOWN");
        num = snprintf(buf, size, CMD_TEARDOWN_AUTH_DIGEST, sess->url, sess->cseq,sess->username,\
        sess->auth_struct.realm,sess->auth_struct.nonce,sess->url,sess->auth_struct.auth_response, sess->sessid);
        if (num < 0x00){
            fprintf(stderr, "%s : snprintf error!\n", __func__);
            return False;
        }
    }

    num = TcpSendData(sock, buf, (uint32_t)num);
    if (num < 0){
        fprintf(stderr, "%s : Send Error\n", __func__);
        return False;
    }

    return True;
}

int32_t RtspTeardownCommand(RtspSession *sess)
{
    int32_t num;
    int32_t size = sizeof(sess->buffctrl.buffer);
    int32_t sock = sess->sockfd;
    char *buf = sess->buffctrl.buffer;

#ifdef RTSP_DEBUG
    printf("++++++++++++++++ TEARDOWN: command ++++++++++++++++++++++++++++\n");
#endif
    if (False == RtspSendTeardownCommand(sess))
        return False;

#ifdef RTSP_DEBUG
    printf("TEARDOWN Request: %s\n", buf);
#endif

    memset(buf, '\0', size);
    num = RtspReceiveResponse(sock, &sess->buffctrl);
    if (num <= 0) {
        fprintf(stderr, "Error: Server did not respond properly, closing...");
        return False;
    }

#ifdef RTSP_DEBUG
    printf("TEARDOWN Reply: %s\n", buf);
#endif

    switch (RtspCheckResponseStatus(buf))
    {
        case ST_OK:
        {
            sess->status = RTSP_QUIT;
            return True;
        }
        case ST_UNAUTHORIZED:
        {
            sess->status = RTSP_GET_PARAMETER;
            ParseUnauthorizedMess(buf,num,sess);
            return True;
        }
        default:
        {

        }
    }
    return False;
}

static RtspCmdHdl rtspcmdhdl[] = {{RTSP_OPTIONS, RtspOptionsCommand},
                                {RTSP_DESCRIBE, RtspDescribeCommand},
                                {RTSP_SETUP, RtspSetupCommand},
                                {RTSP_PLAY, RtspPlayCommand},
                                {RTSP_GET_PARAMETER, RtspGetParameterCommand},
                                {RTSP_TEARDOWN, RtspTeardownCommand},
                                {RTSP_KEEPALIVE, RtspKeepAliveCommand}};

int32_t RtspStatusMachine(RtspSession *sess)
{
    int32_t size = sizeof(rtspcmdhdl)/sizeof(RtspCmdHdl);
    int32_t idx  = 0x00;

    for (idx = 0x00; idx < size; idx++){
        if (sess->status == rtspcmdhdl[idx].cmd){
            if (False == rtspcmdhdl[idx].handle(sess)){
                fprintf(stderr, "Error: Command wasn't supported.\n");
                return False;
            }
            RtspIncreaseCseq(sess);
        }
    }

    return True;
}
