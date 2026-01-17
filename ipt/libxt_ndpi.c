#include <stdio.h>
#include <string.h>
#include <xtables.h>
#include "xt_ndpi.h"

#define NDPI_OPT_OFFSET 100

static char *prot_long_str[] = { NDPI_PROTOCOL_LONG_STRING };
static char *prot_short_str[] = { NDPI_PROTOCOL_SHORT_STRING };

/* Используем современную структуру для nf_tables */
static struct xt_option_entry ndpi_mt_opts_x6[NDPI_LAST_NFPROTO + 1];

static void ndpi_mt_help(void) {
    int i;
    printf("ndpi match options:\n");
    for (i = 1; i < NDPI_LAST_NFPROTO; i++) {
        if (prot_short_str[i] != NULL)
            printf("--%-20s Match for %s\n", prot_short_str[i], prot_long_str[i]);
    }
}

/* Функция проверки пустоты маски (безопасная реализация) */
static int is_mask_empty(const NDPI_PROTOCOL_BITMASK *mask) {
    int i;
    for (i = 0; i < NDPI_NUM_FDS_BITS; i++) {
        if (mask->fds_bits[i] != 0) return 0;
    }
    return 1;
}

/* Современный парсер X6 */
static void ndpi_mt_x6_parse(struct xt_option_call *cb) {
    struct xt_ndpi_mtinfo *info = cb->data;
    // Вычитаем смещение, чтобы вернуться к индексу nDPI (1, 2, 3...)
    unsigned int proto_id = cb->entry->id - NDPI_OPT_OFFSET;

    if (proto_id > 0 && proto_id < NDPI_LAST_NFPROTO) {
        NDPI_ADD_PROTOCOL_TO_BITMASK(info->flags, proto_id);
    }
}

/* Проверка параметров перед отправкой в ядро */
static void ndpi_mt_x6_check(struct xt_fcheck_call *cb) {
    struct xt_ndpi_mtinfo *info = cb->data;
    if (is_mask_empty(&info->flags)) {
        xtables_error(PARAMETER_PROBLEM, "xt_ndpi: You must specify at least one protocol");
    }
}

static void ndpi_mt_print(const void *ip, const struct xt_entry_match *match, int numeric) {
    const struct xt_ndpi_mtinfo *info = (const void *)match->data;
    int i;
    printf(" ndpi ");
    for (i = 1; i < NDPI_LAST_NFPROTO; i++) {
        if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags, i)) 
            printf("%s ", prot_short_str[i]);
    }
}

static void ndpi_mt_save(const void *ip, const struct xt_entry_match *match) {
    const struct xt_ndpi_mtinfo *info = (const void *)match->data;
    int i;
    for (i = 1; i < NDPI_LAST_NFPROTO; i++) {
        if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags, i)) 
            printf(" --%s", prot_short_str[i]);
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
    .x6_parse      = ndpi_mt_x6_parse,
    .x6_fcheck     = ndpi_mt_x6_check,
    .print         = ndpi_mt_print,
    .save          = ndpi_mt_save,
    .x6_options    = ndpi_mt_opts_x6,
};

void __attribute__((constructor)) libxt_ndpi_setup(void) {
    int i;
    int opt_idx = 0;
    memset(ndpi_mt_opts_x6, 0, sizeof(ndpi_mt_opts_x6));

    for (i = 1; i < NDPI_LAST_NFPROTO; i++) {
        if (prot_short_str[i] != NULL && strlen(prot_short_str[i]) > 0) {
            ndpi_mt_opts_x6[opt_idx].name = prot_short_str[i];
            ndpi_mt_opts_x6[opt_idx].type = XTTYPE_NONE;
            // Добавляем смещение, чтобы избежать конфликта с системными ID (0-64)
            ndpi_mt_opts_x6[opt_idx].id   = i + NDPI_OPT_OFFSET; 
            opt_idx++;
        }
    }
    xtables_register_match(&ndpi_mt_reg);
}