#include <stdio.h>
#include <string.h>
#include <xtables.h>
#include "xt_ndpi.h"

/* Список имен протоколов из nDPI */
static char *prot_short_str[] = { NDPI_PROTOCOL_SHORT_STRING };

enum {
    O_PROTO = 1,
};

/* 1. Определение опций */
static const struct xt_option_entry ndpi_mt_opts_x6[] = {
    {.name = "proto", .id = O_PROTO, .type = XTTYPE_STRING, .flags = XTOPT_MAND},
    {.name = NULL}
};

/* 2. Помощь */
static void ndpi_mt_help(void) {
    printf("ndpi match options:\n"
           " --proto <name>  Match for specific protocol (e.g. bittorrent, telegram, ssh)\n");
}

/* 3. Парсер */
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

/* 4. Проверка на пустоту */
static void ndpi_mt_x6_check(struct xt_fcheck_call *cb) {
    struct xt_ndpi_mtinfo *info = cb->data;
    int i, found = 0;

    for (i = 0; i < NDPI_NUM_FDS_BITS; i++) {
        if (info->flags.fds_bits[i] != 0) {
            found = 1;
            break;
        }
    }
    if (!found)
        xtables_error(PARAMETER_PROBLEM, "xt_ndpi: You must specify --proto <name>");
}

/* 5. Вывод (iptables -L) */
static void ndpi_mt_print(const void *ip, const struct xt_entry_match *match, int numeric) {
    const struct xt_ndpi_mtinfo *info = (const void *)match->data;
    int i;
    printf(" ndpi proto");
    for (i = 1; i < NDPI_LAST_NFPROTO; i++) {
        if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags, i)) 
            printf(" %s", prot_short_str[i] ? prot_short_str[i] : "unknown");
    }
}

/* 6. Сохранение (iptables-save) */
static void ndpi_mt_save(const void *ip, const struct xt_entry_match *match) {
    const struct xt_ndpi_mtinfo *info = (const void *)match->data;
    int i;
    for (i = 1; i < NDPI_LAST_NFPROTO; i++) {
        if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags, i)) 
            printf(" --proto %s", prot_short_str[i] ? prot_short_str[i] : "unknown");
    }
}

/* 7. Регистрация модуля (теперь все функции выше известны компилятору) */
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