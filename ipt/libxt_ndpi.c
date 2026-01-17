#include <stdio.h>
#include <string.h>
#include <xtables.h>
#include "xt_ndpi.h"

/* Определяем ID для битторрента. 
   В nDPI протокол BitTorrent обычно имеет индекс 2, 
   но мы можем назначить любой ID для парсера, главное потом правильно сопоставить */
enum {
    O_BITTORRENT = 1,
};

/* Современная структура опций X6 */
static const struct xt_option_entry ndpi_mt_opts_x6[] = {
    {.name = "bittorrent", .id = O_BITTORRENT, .type = XTTYPE_NONE},
    {.name = NULL} // Терминатор
};

static void ndpi_mt_help(void) {
    printf("ndpi match options:\n"
           "--bittorrent    Match for BitTorrent protocol\n");
}

/* Современный парсер X6 */
static void ndpi_mt_x6_parse(struct xt_option_call *cb) {
    struct xt_ndpi_mtinfo *info = cb->data;

    switch (cb->entry->id) {
        case O_BITTORRENT:
            /* Здесь мы используем константу NDPI_PROTOCOL_BITTORRENT 
               из заголовочных файлов nDPI */
            NDPI_ADD_PROTOCOL_TO_BITMASK(info->flags, NDPI_PROTOCOL_BITTORRENT);
            break;
    }
}

/* Проверка, что хоть что-то выбрано */
static void ndpi_mt_x6_check(struct xt_fcheck_call *cb) {
    struct xt_ndpi_mtinfo *info = cb->data;
    int i, found = 0;

    for (i = 0; i < NDPI_NUM_FDS_BITS; i++) {
        if (info->flags.fds_bits[i] != 0) {
            found = 1;
            break;
        }
    }

    if (!found) {
        xtables_error(PARAMETER_PROBLEM, "xt_ndpi: You must specify --bittorrent");
    }
}

static void ndpi_mt_print(const void *ip, const struct xt_entry_match *match, int numeric) {
    const struct xt_ndpi_mtinfo *info = (const void *)match->data;
    if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags, NDPI_PROTOCOL_BITTORRENT))
        printf(" ndpi bittorrent");
}

static void ndpi_mt_save(const void *ip, const struct xt_entry_match *match) {
    const struct xt_ndpi_mtinfo *info = (const void *)match->data;
    if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags, NDPI_PROTOCOL_BITTORRENT))
        printf(" --bittorrent");
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
    xtables_register_match(&ndpi_mt_reg);
}