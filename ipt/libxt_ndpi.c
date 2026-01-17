#include <stdio.h>
#include <string.h>
#include <xtables.h>
#include "xt_ndpi.h"

static char *prot_short_str[] = { NDPI_PROTOCOL_SHORT_STRING };

enum {
    O_PROTO = 1,
};

static const struct xt_option_entry ndpi_mt_opts_x6[] = {
    {.name = "proto", .id = O_PROTO, .type = XTTYPE_STRING, .flags = XTOPT_MAND},
    {.name = NULL}
};

static void ndpi_mt_help(void) {
    printf("ndpi match options:\n"
           " --proto <name>  Match for specific protocol (e.g. bittorrent, telegram, youtube)\n"
           "Available protocols: use 'ndpi-list' or look at nDPI docs.\n");
}

static void ndpi_mt_x6_parse(struct xt_option_call *cb) {
    struct xt_ndpi_mtinfo *info = cb->data;
    int i, found = 0;

    if (cb->entry->id == O_PROTO) {
        for (i = 1; i < NDPI_LAST_NFPROTO; i++) {
            if (prot_short_str[i] && strcasecmp(cb->arg, prot_short_str[i]) == 0) {
                NDPI_ADD_PROTOCOL_TO_BITMASK(info->flags, i);
                found = 1;
                break;
            }
        }
        if (!found)
            xtables_error(PARAMETER_PROBLEM, "xt_ndpi: Unknown protocol '%s'", cb->arg);
    }
}

// ... функции print и save остаются такими же (они уже умеют выводить имена из маски) ...

static struct xtables_match ndpi_mt_reg = {
    .version       = XTABLES_VERSION,
    .name          = "ndpi",
    .revision      = 0,
    .family        = NFPROTO_IPV4,
    .size          = XT_ALIGN(sizeof(struct xt_ndpi_mtinfo)),
    .userspacesize = XT_ALIGN(sizeof(struct xt_ndpi_mtinfo)),
    .help          = ndpi_mt_help,
    .x6_parse      = ndpi_mt_x6_parse,
    .x6_fcheck     = ndpi_mt_x6_check,
    .print         = ndpi_mt_print,
    .save          = ndpi_mt_save,
    .x6_options    = ndpi_mt_opts_x6,
};

void __attribute__((constructor)) libxt_ndpi_setup(void) {
    xtables_register_match(&ndpi_mt_reg);
}