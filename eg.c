/**
 * @file eg.c
 * Egress command main
 */
#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "eg_cmd.h"

/**
 * Egress commands definition
 */
static struct eg_command {
    char *name;
    char *desc;
    int (*func)(int, char **);
} commands[] = {
    {
        .name = "encode",
        .desc = "convert text to pcap",
        .func = eg_encode_main
    },
    {
        .name = "decode",
        .desc = "convert pcap to text",
        .func = eg_decode_main
    },
    {
        .name = "inject",
        .desc = "inject frame to interface",
        .func = eg_inject_main
    },
    {}
};

/**
 * print usage
 */
static void usage()
{
    struct eg_command *cmd;

    printf("usage: eg COMMAND [ARGS]\n");
    printf("\n");

    printf("commands are:\n");
    for (cmd = commands; cmd->name != NULL; cmd++) {
        printf("   %-8s  %s\n", cmd->name, cmd->desc);
    }
}

/**
 * find command
 *
 * @param[in] name command name
 *
 * @return encoder (NULL if not found)
 */
static struct eg_command *eg_find_command(char *name)
{
    struct eg_command *cmd;
    struct eg_command *submatch = NULL;
    int nmatch = 0;

    for (cmd = commands; cmd->name != NULL; cmd++) {
        if (!strcasecmp(cmd->name, name)) {
            return cmd;
        }
        if (!strncasecmp(cmd->name, name, strlen(name))) {
            submatch = cmd;
            nmatch++;
        }
    }
    if (nmatch == 1) {
        return submatch;
    }
    return NULL;
}

/**
 * eg main
 *
 * @param[in] argc arguments count
 * @param[in] argv arguments value
 */
int main(int argc, char *argv[])
{
    struct eg_command *c;

    argc--;
    argv++;
    if (argc <= 0) {
        usage();
        exit(EXIT_SUCCESS);
    }

    c = eg_find_command(argv[0]);
    if (c) {
        return c->func(argc, argv);
    }
    fprintf(stderr, "Invalid command: %s\n", argv[0]);
    usage();
    exit(EXIT_FAILURE);
}
