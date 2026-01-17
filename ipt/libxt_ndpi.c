#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <xtables.h>
#include <linux/version.h>
#include "xt_ndpi.h"

static char *prot_long_str[] = { NDPI_PROTOCOL_LONG_STRING };
static char *prot_short_str[] = { NDPI_PROTOCOL_SHORT_STRING };

// Используем макрос для корректного количества опций
static struct option ndpi_mt_opts[NDPI_LAST_NFPROTO + 2];

static void ndpi_mt_help(void)
{
    int i;
    printf("ndpi match options:\n");
    for (i = 1; i < NDPI_LAST_NFPROTO; i++) {
        printf("--%-15s Match for %s protocol\n", 
               prot_short_str[i], prot_long_str[i]);
    }
}

// Современный метод парсинга (x6_parse)
static void ndpi_mt_parse(struct xt_option_call *cb)
{
    struct xt_ndpi_mtinfo *info = cb->data;

    // cb->entry->val содержит ID протокола, который мы записали в opts.val
    if (cb->entry->id >= 1 && cb->entry->id < NDPI_LAST_NFPROTO) {
        NDPI_ADD_PROTOCOL_TO_BITMASK(info->flags, cb->entry->id);
    }
}

/* Вручную определяем проверку маски, так как в библиотеке она может быть скрыта */
static int ndpi_is_bitmask_empty(const NDPI_PROTOCOL_BITMASK *a) {
    int i;
    /* Используем NDPI_NUM_BITS / NDPI_BITS для кросс-версий nDPI */
    for (i = 0; i < NDPI_NUM_FDS_BITS; i++) {
        if (a->fds_bits[i] != 0) return 0;
    }
    return 1;
}

static void ndpi_mt_check(struct xt_fcheck_call *cb)
{
    struct xt_ndpi_mtinfo *info = cb->data;
    
    if (ndpi_is_bitmask_empty(&info->flags)) {
        xtables_error(PARAMETER_PROBLEM, "xt_ndpi: You must specify at least one protocol");
    }
}

static void ndpi_mt_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
    const struct xt_ndpi_mtinfo *info = (const void *)match->data;
    int i;

    printf(" ndpi ");
    for (i = 1; i < NDPI_LAST_NFPROTO; i++) {
        if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags, i) != 0) {
            printf("%s ", prot_long_str[i]);
        }
    }
}

static void ndpi_mt_save(const void *ip, const struct xt_entry_match *match)
{
    const struct xt_ndpi_mtinfo *info = (const void *)match->data;
    int i;

    for (i = 1; i < NDPI_LAST_NFPROTO; i++) {
        if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags, i) != 0) {
            printf(" --%s", prot_short_str[i]);
        }
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
    .x6_parse      = ndpi_mt_parse,
    .x6_fcheck     = ndpi_mt_check,
    .print         = ndpi_mt_print,
    .save          = ndpi_mt_save,
    .x6_options    = ndpi_mt_opts, // Используем именно x6_options вместо extra_opts
};

void __attribute__((constructor)) _INIT (void)
{
    int i;

    // 1. Полностью очищаем память под опции
    memset(ndpi_mt_opts, 0, sizeof(ndpi_mt_opts));

    for (i = 0; i < NDPI_LAST_NFPROTO; i++) {
        if (prot_short_str[i+1] == NULL) break; // Защита от пустых строк

        ndpi_mt_opts[i].name    = prot_short_str[i+1];
        ndpi_mt_opts[i].has_arg = no_argument;
        ndpi_mt_opts[i].flag    = NULL;
        ndpi_mt_opts[i].val     = i + 1;
    }
    // Завершающий элемент массива
    // ndpi_mt_opts[i].name    = NULL;
    // ndpi_mt_opts[i].has_arg = 0;
    // ndpi_mt_opts[i].val     = 0;

    xtables_register_match(&ndpi_mt_reg);
}