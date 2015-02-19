#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <linux/netfilter.h>  /* Defines verdicts (NF_ACCEPT, etc) */
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

    
  
static int callback(struct nfq_q_handle *myQueue, struct nfgenmsg *msg,
                    struct nfq_data *pkt, void *cbData) 
{
      static int i = 0;
      fprintf(stdout, "frame: %d\n", i++);
  
      uint32_t id = 0;
      struct nfqnl_msg_packet_hdr *header;

      fprintf(stdout, "pkt recvd: \n");

      if ((header = nfq_get_msg_packet_hdr(pkt))) 
      {

        fprintf(stdout, "id %d\n", ntohl(header->packet_id) );

        fprintf(stdout, "hw_protocol %xd \n", ntohs(header->hw_protocol));

        fprintf(stdout, "hook %u\n", header->hook);

      }

      // The HW address is only fetchable at certain hook points
      struct nfqnl_msg_packet_hw *macAddr = nfq_get_packet_hw(pkt);
      if (macAddr) 
      {
        fprintf(stdout, "mac len %u\n", ntohs(macAddr->hw_addrlen));
        fprintf(stdout, "addr ");

        uint8_t *addr = macAddr->hw_addr;
        int i;
        for (i = 0; i < ntohs(macAddr->hw_addrlen); i++) 
        {
          fprintf(stdout, "%x:", addr[i]);
        }
        // end if macAddr
        fprintf(stdout, "\n");
      } else 
      {
         fprintf(stdout,"no MAC addr\n");
      }

//      timeval tv;
//      if (!nfq_get_timestamp(pkt, &tv)) {
//        cout << "; tstamp " << tv.tv_sec << "." << tv.tv_usec;
//      } else {
//        cout << "; no tstamp";
//      }
//
//      cout << "; mark " << nfq_get_nfmark(pkt);

      // Note that you can also get the physical devices
      fprintf(stdout,"indev %u\n", nfq_get_indev(pkt));
      fprintf(stdout, "outdev %u\n", nfq_get_outdev(pkt));


      // Print the payload; in copy meta mode, only headers will be included;
      // in copy packet mode, whole packet will be returned.
      unsigned char *pktData;
      int len = nfq_get_payload(pkt, &pktData);
      if (len) {
        fprintf(stdout, "data[%d]: '", len);
        int i;
        for (i = 0; i < len; i++) {
          //if (isprint(pktData[i]))
            fprintf(stdout, "%x", pktData[i]);
          //else
          //  fprintf(stdout, " ");
        }
        fprintf(stdout, "'\n");
        // end data found
      }

      struct iphdr *ip = (struct iphdr*)pktData;

      char sIP[INET_ADDRSTRLEN], dIP[INET_ADDRSTRLEN];

      inet_ntop(AF_INET, &ip->saddr, sIP, sizeof(sIP));
      inet_ntop(AF_INET, &ip->daddr, dIP, sizeof(dIP));

      fprintf(stdout, "%s -> %s\n", sIP, dIP);
      // For this program we'll always accept the packet...
      return nfq_set_verdict(myQueue, id, NF_ACCEPT, 0, NULL);

      // end Callback

}


int main(int argc, char **argv) 
{

  struct nfq_handle *nfqHandle;
  struct nfq_q_handle *myQueue;
  struct nfnl_handle *netlinkHandle;

  int fd, res;
  int rc;
  char buf[4096];

  // Get a queue connection handle from the module
  if (!(nfqHandle = nfq_open())) 
  {
    fprintf(stderr, "Error in nfq_open()\n");
    exit(1);
  }

  // Unbind the handler from processing any IP packets
  // Not totally sure why this is done, or if it's necessary...
  if ((rc = nfq_unbind_pf(nfqHandle, AF_INET)) < 0) 
  {
    fprintf(stderr, "Error in nfq_unbind_pf() %d\n", rc);
    exit(1);
  }

  // Bind this handler to process IP packets...
  if (nfq_bind_pf(nfqHandle, AF_INET) < 0) 
  {
    fprintf(stderr, "Error in nfq_bind_pf()\n");
    exit(1);
  }

  // Install a callback on queue 0
  if (!(myQueue = nfq_create_queue(nfqHandle,  0, &callback, NULL))) 
  {
    fprintf(stderr, "Error in nfq_create_queue()\n");
    exit(1);
  }

  // Turn on packet copy mode
  if (nfq_set_mode(myQueue, NFQNL_COPY_PACKET, 0xffff) < 0) 
  {
    fprintf(stderr, "Could not set packet copy mode\n");
    exit(1);
  }

  netlinkHandle = nfq_nfnlh(nfqHandle);
  fd = nfnl_fd(netlinkHandle);

  while ((res = recv(fd, buf, sizeof(buf), 0)) && res >= 0) 
  {
    // I am not totally sure why a callback mechanism is used
    // rather than just handling it directly here, but that
    // seems to be the convention...
    nfq_handle_packet(nfqHandle, buf, res);
    // end while receiving traffic
  }

  nfq_destroy_queue(myQueue);

  nfq_close(nfqHandle);

  return 0;

  // end main
}
