/* PicoTCP Test application */

#include "pico_stack.h"
#include "pico_config.h"
#include "pico_dev_vde.h"
#include "pico_ipv4.h"
#include "pico_socket.h"
#include "pico_dev_tun.h"

#include <poll.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
//struct pico_ip4 inaddr_any = {0x0400280a};
struct pico_ip4 inaddr_any = { };
static char *cpy_arg(char **dst, char *str);

void deferred_exit(unsigned long now, void *arg)
{
  printf("Quitting\n");
  exit(0);
}

/*** APPLICATIONS API: ***/
/* To create a new application, define your initialization
 * function and your callback here */


/**** UDP ECHO ****/
static int udpecho_exit = 0;

void cb_udpecho(uint16_t ev, struct pico_socket *s)
{
  char recvbuf[1400];
  int r=0;
  uint32_t peer;
  uint16_t port;
  if (udpecho_exit)
    return;

  //printf("udpecho> wakeup\n");
  if (ev == PICO_SOCK_EV_RD) {
    do {
      r = pico_socket_recvfrom(s, recvbuf, 1400, &peer, &port);
      if (r > 0) {
        if (strncmp(recvbuf, "end", 3) == 0) {
          printf("Client requested to exit... test successful.\n");
          pico_timer_add(1000, deferred_exit, NULL);
          udpecho_exit++;
        }
        pico_socket_sendto(s, recvbuf, r, &peer, port);
      }
    } while(r>0);
  }

  if (ev == PICO_SOCK_EV_ERR) {
    printf("Socket Error received. Bailing out.\n");
    exit(7);
  }
}

void app_udpecho(char *arg)
{
  struct pico_socket *s;
  char *sport;
  int port = 0;
  uint16_t port_be = 0;
  printf("sport: %s\n", arg);
  cpy_arg(&sport, arg);
  if (sport) {
    port = atoi(sport);
    if (port > 0)
      port_be = short_be(port);
  }
  if (port == 0) {
    port_be = short_be(5555);
  }

  s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &cb_udpecho);
  if (!s)
    exit(1);

  if (pico_socket_bind(s, &inaddr_any, &port_be)!= 0)
    exit(1);

}
/*** END UDP ECHO ***/

/*** TCP ECHO ***/
void cb_tcpecho(uint16_t ev, struct pico_socket *s)
{
  #define BSIZE 1400
  char recvbuf[BSIZE];
  int r=0, w = 0;
  int pos = 0, len = 0;

  //printf("tcpecho> wakeup\n");
  if (ev & PICO_SOCK_EV_RD) {
    do {
      r = pico_socket_read(s, recvbuf + len, BSIZE - len);
      if (r > 0)
        len += r;
    } while(r>0);
  }
  if (ev & PICO_SOCK_EV_CONN) { 
    struct pico_socket *sock_a;
    struct pico_ip4 orig;
    uint16_t port;
    char peer[30];
    sock_a = pico_socket_accept(s, &orig, &port);
    pico_ipv4_to_string(peer, orig.addr);
    printf("Connection established with %s:%d.\n", peer, short_be(port));
  }

  if (ev & PICO_SOCK_EV_FIN) {
    printf("Socket closed. Exit normally. \n");
    pico_timer_add(2000, deferred_exit, NULL);
  }

  if (ev & PICO_SOCK_EV_ERR) {
    printf("Socket Error received. Bailing out.\n");
    exit(1);
  }
  if (ev & PICO_SOCK_EV_CLOSE) {
    printf("Socket received close from peer.\n");
    pico_socket_close(s);
  }

  if (len > pos) {
    do {
      w = pico_socket_write(s, recvbuf + pos, len - pos);
      if (w > 0) {
        pos += w;
        if (pos >= len) {
          pos = 0;
          len = 0;
        }
      }
    } while(w > 0);
  }
}

void app_tcpecho(char *arg)
{
  struct pico_socket *s;
  char *sport = arg;
  int port = 0;
  uint16_t port_be = 0;
  cpy_arg(&sport, arg);
  if (sport) {
    port = atoi(sport);
    port_be = short_be((uint16_t)port);
  }
  if (port == 0) {
    port_be = short_be(5555);
  }

  s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, &cb_tcpecho);
  if (!s)
    exit(1);

  if (pico_socket_bind(s, &inaddr_any, &port_be)!= 0)
    exit(1);

  if (pico_socket_listen(s, 40) != 0)
    exit(1);

}
/*** END TCP ECHO ***/

/*** UDP CLIENT ***/
void udpclient_send(unsigned long now, void *arg) {
  int i, w;
  struct pico_socket *s = (struct pico_socket *)arg;
  char buf[1400] = { };
  char end[4] = "end";
  static int loop = 0;
  for (i = 0; i < 10; i++) {
    w = pico_socket_send(s, buf, 1400);
    if (w <= 0)
      break;
    printf("Written %d bytes.\n", w);
  }

  if (++loop > 100) {
    for (i = 0; i < 3; i++) {
      w = pico_socket_send(s, end, 4);
      if (w <= 0)
        break;
      printf("End!\n");
    }
    pico_timer_add(1000, deferred_exit, NULL);
    return;
  }
  pico_timer_add(100, udpclient_send, s);
}

void cb_udpclient(uint16_t ev, struct pico_socket *s)
{
  char recvbuf[1400];
  int r=0;
  uint32_t peer;
  uint16_t port;

  //printf("udpclient> wakeup\n");
  if (ev & PICO_SOCK_EV_RD) {
    do {
      r = pico_socket_recvfrom(s, recvbuf, 1400, &peer, &port);
    } while(r>0);
  }

  if (ev == PICO_SOCK_EV_ERR) {
    printf("Socket Error received. Bailing out.\n");
    exit(7);
  }

}

void app_udpclient(char *arg)
{
  struct pico_socket *s;
  char *daddr, *dport;
  int port = 0;
  uint16_t port_be = 0;
  struct pico_ip4 inaddr_dst = { };
  char *nxt;

  nxt = cpy_arg(&daddr, arg);
  if (!daddr) {
    fprintf(stderr, " udpclient expects the following format: udpclient:dest_addr[:dest_port]\n");
    exit(255);
  }

  if (nxt) {
    cpy_arg(&dport, arg);
    if (dport) {
      port = atoi(dport);
      if (port > 0)
        port_be = short_be(port);
    }
  }
  if (port == 0) {
    port_be = short_be(5555);
  }

  printf("UDP client started. Sending packets to %s:%d\n", daddr, short_be(port_be));

  s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &cb_udpclient);
  if (!s)
    exit(1);

  pico_string_to_ipv4(daddr, &inaddr_dst.addr);

  if (pico_socket_connect(s, &inaddr_dst, port_be)!= 0)
    exit(1);

  pico_timer_add(100, udpclient_send, s);

}
/*** END UDP CLIENT ***/

/*** TCP CLIENT ***/
#define TCPSIZ (1024 * 1024 * 10)
static char *buffer1;
static char *buffer0;

void compare_results(unsigned long now, void *arg)
{
#ifdef CONSISTENCY_CHECK /* TODO: Enable */
  int i;
  printf("Calculating result.... (%p)\n", buffer1);

  if (memcmp(buffer0,buffer1,TCPSIZ) == 0)
    exit(0);

  for (i = 0; i < TCPSIZ; i++) {
    if (buffer0[i] != buffer1[i]) {
      fprintf(stderr, "Error at byte %d - %c!=%c\n", i, buffer0[i], buffer1[i]);
      exit(115);
    }
  }
#endif
  exit(0);

}

void cb_tcpclient(uint16_t ev, struct pico_socket *s)
{
  static int w_size = 0;
  static int r_size = 0;
  static int closed = 0;
  int r,w;

  //printf("tcpclient> wakeup\n");
  if (ev & PICO_SOCK_EV_RD) {
    do {
      r = pico_socket_read(s, buffer1 + r_size, TCPSIZ - r_size);
      if (r > 0) {
        r_size += r;
      }
      if (r < 0)
        exit(5);
    } while(r>0);
  }
  if (ev & PICO_SOCK_EV_CONN) { 
    printf("Connection established with server.\n");
  }

  if (ev & PICO_SOCK_EV_FIN) {
    printf("Socket closed. Exit normally. \n");
    pico_timer_add(2000, compare_results, NULL);
    return;
  }

  if (ev & PICO_SOCK_EV_ERR) {
    printf("Socket Error received. Bailing out.\n");
    exit(1);
  }
  if (ev & PICO_SOCK_EV_CLOSE) {
    printf("Socket received close from peer - Wrong case!\n");
    pico_socket_close(s);
    exit(1);
  }

  if (w_size < TCPSIZ) {
    do {
      w = pico_socket_write(s, buffer0 + w_size, TCPSIZ - w_size);
      if (w > 0) {
        w_size += w;
      if (w < 0)
        exit(5);
      }
    } while(w > 0);
  } else {
    if (!closed) {
      pico_socket_shutdown(s, PICO_SHUT_WR);
      printf("Called shutdown()\n");
      closed = 1;
    }
  }
}

void app_tcpclient(char *arg)
{
  struct pico_socket *s;
  char *dport;
  char *dest;
  int port = 0, i;
  uint16_t port_be = 0;
  struct pico_ip4 server_addr;
  char *nxt = cpy_arg(&dest, arg);
  if (!dest) {
    fprintf(stderr, "tcpclient needs the following format: tcpclient:dst_addr[:dport]\n");
    exit(255);
  }
  if (nxt) {
    printf("Next arg: %s\n", nxt);
    cpy_arg(&dport, nxt);
    printf("Dport: %s\n", dport);
  }
  if (dport) {
    port = atoi(dport);
    port_be = short_be((uint16_t)port);
  }
  if (port == 0) {
    port_be = short_be(5555);
  }

  buffer0 = malloc(TCPSIZ);
  buffer1 = malloc(TCPSIZ);
  printf("Buffer1 (%p)\n", buffer1);
  for (i = 0; i < TCPSIZ; i++) {
    char c = (i % 26) + 'a';
    buffer0[i] = c;
  }
  memset(buffer1, 'a', TCPSIZ);
  printf("Connecting to: %s:%d\n", dest, short_be(port_be));

  s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, &cb_tcpclient);
  if (!s)
    exit(1);

  pico_string_to_ipv4(dest, &server_addr.addr);
  pico_socket_connect(s, &server_addr, port_be);

}
/*** END TCP CLIENT ***/


/** From now on, parsing the command line **/

#define NXT_MAC(x) ++x[5]

/* Copy a string until the separator, 
terminate it and return the next index, 
or NULL if it encounters a EOS */
static char *cpy_arg(char **dst, char *str)
{
  char *p, *nxt = NULL;
  char *start = str;
  p = str;
  while (p) {
    if ((*p == ':') || (p == '\0')) {
      *p = (char)0;
      nxt = p + 1;
      if (*nxt == 0)
        nxt = 0;
      printf("dup'ing %s\n", start);
      *dst = strdup(start);
      break;
    }
    p++;
  }
  return nxt;
}


void usage(char *arg0)
{
  printf("Usage: %s [--vde name:sock:address:netmask[:gateway]] [--vde ...] [--tun name:address:netmask[:gateway]] [--tun ...] [--app name[:args]]\n\n\n", arg0);
  printf("\tall arguments can be repeated, e.g. to run on multiple links or applications\n");
  printf("\t*** --app arguments must be at the end  ***\n");
  exit(255);
}

#define IF_APPNAME(x) if(strcmp(x, name) == 0)

int main(int argc, char **argv)
{
  unsigned char macaddr[6] = {0,0,0,0xa,0xb,0x0};
  uint16_t *macaddr_low = (uint16_t *) (macaddr + 2);
  struct pico_device *dev = NULL;

  struct option long_options[] = {
    {"help",0 , 0, 'h'},
    {"vde",1 , 0, 'v'},
    {"tun", 1, 0, 't'},
    {"app", 1, 0, 'a'},
    {0,0,0,0}
  };
  int option_idx = 0;
  int c;

  *macaddr_low ^= getpid();
  printf("My macaddr base is: %02x %02x\n", macaddr[2], macaddr[3]);

  pico_stack_init();
  /* Parse args */
  while(1) {
    c = getopt_long(argc, argv, "v:t:a:h", long_options, &option_idx);
    if (c < 0)
      break;
    switch(c) {
      case 'h':
        usage(argv[0]);
        break;
      case 't':
      {
        char *nxt, *name = NULL, *addr = NULL, *nm = NULL, *gw = NULL;
        struct pico_ip4 ipaddr, netmask, gateway;
        do {
          nxt = cpy_arg(&name, optarg);
          if (!nxt) break;
          nxt = cpy_arg(&addr, nxt);
          if (!nxt) break;
          nxt = cpy_arg(&nm, nxt);
          if (!nxt) break;
          cpy_arg(&gw, nxt);
        } while(0);
        if (!nm) {
          fprintf(stderr, "Tun: bad configuration...\n");
          exit(1);
        }
        dev = pico_tun_create(name);
        if (!dev) {
          perror("Creating tun");
          exit(1);
        }
        pico_string_to_ipv4(addr, &ipaddr.addr);
        pico_string_to_ipv4(nm, &netmask.addr);
        pico_ipv4_link_add(dev, ipaddr, netmask);
        if (gw && *gw) {
          pico_string_to_ipv4(gw, &gateway.addr);
          pico_ipv4_route_add(ipaddr, netmask, gateway, 1, NULL);
        }
      }
      break;
    case 'v':
      {
        char *nxt, *name = NULL, *sock = NULL, *addr = NULL, *nm = NULL, *gw = NULL;
        struct pico_ip4 ipaddr, netmask, gateway;
        do {
          nxt = cpy_arg(&name, optarg);
          if (!nxt) break;
          nxt = cpy_arg(&sock, nxt);
          if (!nxt) break;
          nxt = cpy_arg(&addr, nxt);
          if (!nxt) break;
          nxt = cpy_arg(&nm, nxt);
          if (!nxt) break;
          cpy_arg(&gw, nxt);
        } while(0);
        if (!nm) {
          fprintf(stderr, "Vde: bad configuration...\n");
          exit(1);
        }
        dev = pico_vde_create(sock, name, macaddr);
        NXT_MAC(macaddr);
        if (!dev) {
          perror("Creating vde");
          exit(1);
        }
        pico_string_to_ipv4(addr, &ipaddr.addr);
        pico_string_to_ipv4(nm, &netmask.addr);
        pico_ipv4_link_add(dev, ipaddr, netmask);
        if (gw && *gw) {
          pico_string_to_ipv4(gw, &gateway.addr);
          pico_ipv4_route_add(ipaddr, netmask, gateway, 1, NULL);
        }
      }
      break;
    case 'a':
      {
        char *name = NULL, *args = NULL;
        args = cpy_arg(&name, optarg);
        IF_APPNAME("udpecho") {
          app_udpecho(args);
        }
        else IF_APPNAME("tcpecho") {
          app_tcpecho(args);
        }
        else IF_APPNAME("udpclient") {
          app_udpclient(args);
        }
        else IF_APPNAME("tcpclient") {
          app_tcpclient(args);
        }
        else {
          fprintf(stderr, "Unknown application %s\n", name);
          usage(argv[0]);
        }
      }
      break;
    }
  }
  if (!dev) {
    printf("nodev");
    usage(argv[0]);
  }


  printf("Entering loop...\n");
  while(1) {
    pico_stack_tick();
    usleep(2000);
  }
}