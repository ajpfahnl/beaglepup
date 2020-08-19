#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <mraa/gpio.h>
#include <mraa/aio.h>
#include <getopt.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

// GPIO_50 is MRAA 60
// Analog A0/A1 is MRAA 1
// ensure 5V

// new option vars
static int uid;
char * address;
static int portnum;

// other new data
static int sockfd;
static struct sockaddr_in serv_addr;
struct hostent * server;

SSL_CTX * new_context;
SSL * ssl_client;

// I/O
mraa_aio_context temp_io;
mraa_gpio_context button;

// constant vars for temp conversion
const int B = 4275;
const int R0 = 100000;

// time variables
time_t raw_time;
struct tm * local_time;

// log fd
int log_fd;

// buffer size
const int size = 512;

// options
static int period = 1; 			// sampling interval in seconds
static int report_fahrenheit = 1; 	// 0 if report Celsius
static int log_set = 0; 		// no logging by default
static char * logname;			// name of log to be created
static int report = 1;          // default create report, change with "STOP"

// stop condition
sig_atomic_t volatile run_flag = 1;
sig_atomic_t volatile last_call = 0;

int SSL_write_wrap(SSL *ssl, const void *buf, int num)
{
    int wb;
    if ((wb = SSL_write(ssl, buf, num)) <= 0)
    {
        fprintf(stderr, "Error with SSL_write()\n");
        exit(2);
    }
    return wb;
}
int SSL_read_wrap(SSL *ssl, void *buf, int num)
{
    int rb;
    if ((rb = SSL_read(ssl, buf, num)) <= 0)
    {
        fprintf(stderr, "Error with SSL_read()\n");
        exit(2);
    }
    return rb;
}

void interrupt_handler()
{
    // get time
    time(&raw_time);
    local_time = localtime(&raw_time);
    
    // create report
    char report_buf[size];
    int bytes;
    bytes = sprintf(report_buf, "%.2d:%.2d:%.2d SHUTDOWN\n",
                    local_time->tm_hour,
                    local_time->tm_min,
                    local_time->tm_sec);
    SSL_write_wrap(ssl_client, report_buf, bytes);
    
    if (log_set)
    {   
        dprintf(log_fd, "%s", report_buf);
    }
    mraa_aio_close(temp_io);
    EVP_cleanup();
    exit(0);	
}

void openTLS()
{
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    
    // create context
    new_context = SSL_CTX_new(TLSv1_client_method());
    if (new_context == NULL)
    {
        fprintf(stderr, "Error with SSL_CTX_new()\n");
        exit(2);
    }
    
    // create struct to hold connection data
    ssl_client = SSL_new(new_context);
    if (ssl_client == NULL)
    {
        fprintf(stderr, "Error with SSL_new()\n");
        exit(2);
    }
    
    // create new socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        fprintf(stderr, "Error creating socket: %s\n", strerror(errno));
        exit(2);
    }
    
    // get network host entry
    server = gethostbyname(address);
    if (server == NULL) {
        fprintf(stderr, "Invalid host: %s\n", hstrerror(h_errno));
        exit(1);
    }
    
    // set fields in serv_addr
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr,
          (char *)&serv_addr.sin_addr.s_addr,
          server->h_length);
    serv_addr.sin_port = htons(portnum);
    
    // connect to server
    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        fprintf(stderr, "Error initiating connection on socket: %s\n", strerror(errno));
        exit(2);
    }
    
    // SSL connection
    if (SSL_set_fd(ssl_client, sockfd) == 0)
    {
        fprintf(stderr, "Error setting SSL socket fd\n");
        exit(2);
    }
    if (SSL_connect(ssl_client) != 1)
    {
        fprintf(stderr, "Error with SSL_connect()");
        exit(2);
    }
}

// otdin options while program running
void stdin_cmd(char * str)
{
    int match = 1;
    // check for commands
    if (strcmp("SCALE=F", str) == 0)
    {
        report_fahrenheit = 1;
    }
    else if (strcmp("SCALE=C", str) == 0)
    {
        report_fahrenheit = 0;
    }
    else if (strncmp("PERIOD=", str, 7) == 0)
    {
        period = atoi(&str[7]);
    }
    else if (strcmp("STOP", str) == 0)
    {
        report = 0;
    }
    else if (strcmp("START", str) == 0)
    {
        report = 1;
    }
    else if (strncmp("LOG ", str, 4) == 0)
    {
        // only log
    }
    else if (strcmp("OFF", str) == 0)
    {
        if (log_set)
        {
            dprintf(log_fd, "%s\n", str);
        }
        interrupt_handler();
    }
    else
    {
        match = 0;
    }
    // log
    if (match && log_set)
    {
        dprintf(log_fd, "%s\n", str);
    }
    
}

static struct option longopts[] = 
{
    {"period", required_argument, NULL, 'p'},
    {"scale", required_argument, NULL, 's'},
    {"log", required_argument, NULL, 'l'},
    {"id", required_argument, NULL, 'i'},
    {"host", required_argument, NULL, 'h'},
    {0,0,0,0}
};

int main(int argc, char * argv[])
{
    // get options
    char usage[] = "usage: ./lab4c_tls portnum [--period=#] [--scale=C/F] --log=<filename> --id=<UID> --host=<host>";
    int required = 0;
    char * scale;
    int opt;
    while ((opt = getopt_long(argc, argv, "", longopts, NULL)) != -1)
    {
        switch(opt)
        {
            case 'p':
                period = atoi(optarg);
                break;
            case 's':
                scale = optarg;
                if (strlen(scale) != 1)
                {
                    fprintf(stderr, "scale option usage: --scale=C/F\n");
                    exit(1);
                }
                switch(scale[0])
                {
                    case 'F':
                        report_fahrenheit = 1;
                        break;
                    case 'C':
                        report_fahrenheit = 0;
                        break;
                    default:
                        fprintf(stderr, "scale option usage: --scale=C/F\n");
                        exit(1);
                }
                break;
            case 'l':
                log_set = 1;
                logname = optarg;
                required += 1;
                break;
            case 'i':
                if (strlen(optarg) != 9)
                {
                    fprintf(stderr, "UID needs to be 9 digits.\n%s\n", usage);
                    exit(1);
                }
                uid = atoi(optarg);
                required += 1;
                break;
            case 'h':
                address = optarg;
                required += 1;
                break;
            default:
                fprintf(stderr, "%s\n", usage);
                exit(1);
        }
    }
    // parse port num (non-switch parameter)
    int firstarg = 1;
    int nonswitch_i;
    for(nonswitch_i=optind; nonswitch_i<argc; nonswitch_i++)
    {
        if (firstarg == 0)
        {
            fprintf(stderr, "%s\n", usage);
            exit(1);
        }
        portnum = atoi(argv[nonswitch_i]);
        firstarg = 0;
        required += 1;
    }
    
    // check required args
    if (required != 4)
    {
        fprintf(stderr, "Required arguments not satisfied.\n%s\n", usage);
        exit(1);
    }
    
    openTLS();
    
    // create log
    if (log_set && (log_fd = open(logname, O_CREAT|O_WRONLY|O_APPEND, 0666)) == -1)
    {
        fprintf(stderr, "Invalid log: %s\n", strerror(errno));
        exit(1);
    }
    
    // set poll for stdin
    struct pollfd fds[1];
    fds[0].fd = sockfd;
    fds[0].events = POLLIN | POLLHUP | POLLERR;    
    
    // temperature variables
    uint16_t raw_temp;
    float R;
    float temp;
    
    // initiate pins
    temp_io = mraa_aio_init(1); // 1 specifies the port
    if (temp_io == NULL)
    {
        fprintf(stderr, "Error with mraa_aio_init(1)\n");
        exit(2);
    }
    
    // send uid and record
    char uid_buf[size];
    int bytes;
    bytes = sprintf(uid_buf, "ID=%d\n", uid);
    SSL_write_wrap(ssl_client, uid_buf, bytes);
    dprintf(log_fd, "%s", uid_buf);
    
    // normal operations
    char report_buf[size];
    char buf[size];
    char buf_prev[2*size];
    char cmd_buf[size];
    int cmd_i, buf_i, rcount;
    int buf_prev_len = 0;
    while(run_flag)
    {
        // get time
        time(&raw_time);
        local_time = localtime(&raw_time);
        
        // poll stdin
        if (poll(fds, 1, 0) == -1)
        {
            fprintf(stderr, "Error polling: %s\n", strerror(errno));
            exit(2);
        }
        
        // read from stdin
        if (fds[0].revents & POLLIN)
        {
            rcount = SSL_read_wrap(ssl_client, buf, size);
            
            // combine read with previous partial command
            memcpy(&buf_prev[buf_prev_len], buf, rcount);
            cmd_i = 0; // index of beginning of command
            for (buf_i=0; buf_i<rcount+buf_prev_len; buf_i++)
            {
                // parsed full command
                if (buf_prev[buf_i] == '\n')
                {
                    cmd_buf[buf_i-cmd_i] = '\0';
                    stdin_cmd(cmd_buf);
                    cmd_i = buf_i + 1;
                }
                // keep adding to command buffer
                else
                {
                    cmd_buf[buf_i-cmd_i] = buf_prev[buf_i];
                }
            }
            // partial commands --> copy to new buffer for use in next cycle
            buf_prev_len = rcount+buf_prev_len-cmd_i;
            memcpy(buf_prev, &buf[cmd_i], buf_prev_len);
        }
        
        // temperature in Celsius
        raw_temp = mraa_aio_read(temp_io);
        R = 1023.0/raw_temp-1.0;
        R=R0*R;
        temp = 1.0/(log(R/R0)/B+1/298.15)-273.15;
        
        // convert to Fahrenheit
        if (report_fahrenheit)
        {
            temp = (temp * (9.0F/5.0F)) + 32.0F;
        }
        
        if (report) // report
        {
            bytes = sprintf(report_buf, "%.2d:%.2d:%.2d %.1f\n", 
                            local_time->tm_hour,
                            local_time->tm_min,
                            local_time->tm_sec,
                            temp);
            SSL_write_wrap(ssl_client, report_buf, bytes);
        }
        
        if (log_set && report)
        {
            dprintf(log_fd, "%s", report_buf);
        }
        
        // wait
        usleep(period * 1000000); // argument in microseconds
    }
    exit(0);
}	
