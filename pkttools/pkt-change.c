#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/time.h>

#include "argument.h"
#include "asm_val.h"
#include "asm_field.h"
#include "asm_entry.h"
#include "asm_list.h"
#include "assemble.h"
#include "disasm.h"
#include "text.h"
#include "change.h"
#include "lib.h"

static void help()
{
  fprintf(stderr, "pkt-change\n");
  fprintf(stderr, "\tInput packets from stdin and change fields.\n\n");
  fprintf(stderr, "EXAMPLE:\n");
  fprintf(stderr, "\t$ pkt-recv -i eth0 | pkt-change | pkt-send -i eth1\n");
  fprintf(stderr, "\t$ cat packet.txt | pkt-change | pkt-analyze\n\n");
  fprintf(stderr, "OPTIONS:\n");
  fprintf(stderr, "\t-h\t\tOutput help of options.\n");
  fprintf(stderr, "\t-k\t\tOutput help of keys.\n");
  fprintf(stderr, "\t-b <size>\tBuffer size.\n");
  fprintf(stderr, "\t-r\t\tReverse filter rule.\n");
  fprintf(stderr, "\t-a\t\tOutput field assembly.\n");
  exit(0);
}

static void help_key()
{
  fprintf(stderr, "FILTER KEYS:\n");
  pkt_asm_field_output_key_list(stderr, "\t");
  exit(0);
}

static int bufsize = PKT_BUFFER_SIZE_DEFAULT;
static int filrev  = ARGUMENT_FLAG_OFF;
static int asmlist = ARGUMENT_FLAG_OFF;

static Argument args[] = {
  { "-h", ARGUMENT_TYPE_FUNCTION, help     },
  { "-k", ARGUMENT_TYPE_FUNCTION, help_key },
  { "-b", ARGUMENT_TYPE_INTEGER, &bufsize  },
  { "-r", ARGUMENT_TYPE_FLAG_ON, &filrev   },
  { "-a", ARGUMENT_TYPE_FLAG_ON, &asmlist  },
  { NULL, ARGUMENT_TYPE_NONE   , NULL      },
};

static int terminated = 0;
static void sigint_handler(int value)
{
  terminated = 1;
}

int main(int argc, char *argv[])
{
  int size, r;
  char *buffer;
  struct timeval tm;
  pkt_asm_list_t list;

  argument_read(&argc, argv, args);

  buffer = malloc(bufsize);
  if (buffer == NULL)
    error_exit("Out of memory.\n");

  while (!terminated) {
    list = pkt_asm_list_create();
    size = pkt_text_read(stdin, buffer, bufsize, NULL, NULL, &tm, list);
    if (size < 0)
      break;
    if (size == bufsize)
      error_exit("Out of buffer.\n");

    pkt_assemble_ethernet(list, buffer, size);
    list = pkt_asm_list_destroy(list);

    if (pkt_asm_list_filter_args(NULL, argc, argv) == 0) {
      list = pkt_asm_list_create();
      pkt_disasm_ethernet(list, buffer, size);
      r = pkt_asm_list_filter_args(list, argc, argv);
      list = pkt_asm_list_destroy(list);
      if (r >= 0) {
	if (filrev) r = !r;
	if (r == 0) continue;
      }
    }

    size = pkt_change_ethernet(buffer, size);
    if (size < 1)
      continue;

    list = pkt_asm_list_create();
    pkt_asm_list_read_args(list, argc, argv);
    pkt_assemble_ethernet(list, buffer, size);
    list = pkt_asm_list_destroy(list);

    if (asmlist) {
      list = pkt_asm_list_create();
      pkt_disasm_ethernet(list, buffer, size);
    }

    signal(SIGINT , sigint_handler);
    signal(SIGTERM, sigint_handler);
    pkt_text_write(stdout, buffer, size, size, &tm, list);
    signal(SIGINT , SIG_DFL);
    signal(SIGTERM, SIG_DFL);

    list = pkt_asm_list_destroy(list);
  }

  fflush(stdout);
  free(buffer);

  return 0;
}
