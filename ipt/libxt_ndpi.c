#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <xtables.h>
#include "xt_ndpi.h"

static char *prot_short_str[] = { NDPI_PROTOCOL_SHORT_STRING };

/* Используем классический struct option для парсинга аргументов командной строки */
static const struct option ndpi_mt_opts[] = {
    {.name = "proto", .has_arg = required_argument, .val = 'p'},
    {NULL}
};

static void ndpi_mt_help(void) {
    printf("ndpi match options:\n"
           " --proto <name>  Match for specific protocol (e.g. bittorrent, telegram)\n");
}

/* Используем стандартный парсер .parse (совместим с nf_tables) */
static int ndpi_mt_parse(int c, char **argv, int invert, unsigned int *flags,
                         const void *entry, struct xt_entry_match **match) {
    struct xt_ndpi_mtinfo *info = (void *)(*match)->data;
    int i, found = 0;

    switch (c) {
        case 'p': // Соответствует .val = 'p' в struct option
            if (*flags)
                xtables_error(PARAMETER_PROBLEM, "xt_ndpi: Only one --proto is allowed per rule");
            
            for (i = 1; i < NDPI_LAST_NFPROTO; i++) {
                if (prot_short_str[i] && strcasecmp(optarg, prot_short_str[i]) == 0) {
                    NDPI_ADD_PROTOCOL_TO_BITMASK(info->flags, i);
                    found = 1;
                    break;
                }
            }
            if (!found)
                xtables_error(PARAMETER_PROBLEM, "xt_ndpi: Unknown protocol '%s'", optarg);
            
            *flags = 1;
            return 1;
    }
    return 0;
}

static void ndpi_mt_check(unsigned int flags) {
    if (!flags)
        xtables_error(PARAMETER_PROBLEM, "xt_ndpi: You must specify --proto <name>");
}

static void ndpi_mt_print(const void *ip, const struct xt_entry_match *match, int numeric) {
    const struct xt_ndpi_mtinfo *info = (const void *)match->data;
    int i;
    printf(" ndpi proto");
    for (i = 1; i < NDPI_LAST_NFPROTO; i++) {
        if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags, i)) 
            printf(" %s", prot_short_str[i] ? prot_short_str[i] : "unknown");
    }
}

static void ndpi_mt_save(const void *ip, const struct xt_entry_match *match) {
    const struct xt_ndpi_mtinfo *info = (const void *)match->data;
    int i;
    for (i = 1; i < NDPI_LAST_NFPROTO; i++) {
        if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags, i)) 
            printf(" --proto %s", prot_short_str[i] ? prot_short_str[i] : "unknown");
    }
}

static struct xtables_match ndpi_mt_reg = {
    .version       = XTABLES_VERSION,
    .name          = "ndpi",
    .revision      = 0,
    .family        = NFPROTO_IPV4,
    .size          = XT_ALIGN(sizeof(struct xt_ndpi_mtinfo)),
    .userspacesize = XT_ALIGN(sizeof(struct xt_ndpi_mtinfo)),
    .help          = ndpi_mt_help,
    .parse         = ndpi_mt_parse,
    .final_check   = ndpi_mt_check,
    .print         = ndpi_mt_print,
    .save          = ndpi_mt_save,
    .extra_opts    = ndpi_mt_opts,
};

void __attribute__((constructor)) libxt_ndpi_setup(void) {
    xtables_register_match(&ndpi_mt_reg);
}