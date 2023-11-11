// SPDX-License-Identifier: MIT

#include "common.h"
#include "utils.h"
#include <libudev.h>

#define TOOL_VERSION 1

enum selection {
    SELECT_EVERYTHING = 0,
    SELECT_METAINFORMATION = 1,
    SELECT_IDENTIFY = 2,
    SELECT_DISCOVERY_0 = 3,
    SELECT_DISCOVERY_1 = 4,
    SELECT_DISCOVERY_2 = 5,
    SELECT_DISCOVERY_2_EXTRA = 6,
    SELECT_RNG = 7,
};

static void print_comma_start(int *first)
{
    if (*first) {
        printf(",\n");
    }

    *first = 1;
}

static void print_uid_key(const unsigned char *uid, int spaces, int is_first)
{
    if (!is_first) {
        printf(",\n");
    }
    for (int i = 0; i < spaces; ++i) {
        printf(" ");
    }
    printf("\"0x");
    for (int i = 0; i < 8; ++i) {
        printf("%02x", uid[i]);
    }
    printf("\": {\n");
}

static void print_level_0_discovery(struct disk_device *dev)
{
    int first = 0;

    if (dev->features.tper.shared.feature_code) {
        struct level_0_discovery_tper_feature *body = &dev->features.tper;

        print_comma_start(&first);
        printf("  \"TPer Feature\": {\n"
               "    \"Version\": %i,\n"
               "    \"ComID Mgmt Supported\": %i,\n"
               "    \"Streaming Supported\": %i,\n"
               "    \"Buffer Mgmt Supported\": %i,\n"
               "    \"ACK/NAK Supported\": %i,\n"
               "    \"Async Supported\": %i,\n"
               "    \"Sync Supported\": %i\n"
               "  }",
               body->shared.descriptor_version, body->comID_mgmt_supported, body->streaming_supported,
               body->buffer_mgmt_supported, body->ack_nack_supported, body->async_supported, body->sync_supported);
    }

    if (dev->features.locking.shared.feature_code) {
        struct level_0_discovery_lockin_feature *body = &dev->features.locking;

        print_comma_start(&first);
        printf("  \"Locking Feature\": {\n"
               "    \"Version\": %i,\n"
               "    \"HW Reset for LOR/DOR Supported\": %i,\n"
               "    \"MBR Shadowing Not Supported\": %i,\n"
               "    \"MBR Done\": %i,\n"
               "    \"MBR Enabled\": %i,\n"
               "    \"Media Encryption\": %i,\n"
               "    \"Locked\": %i,\n"
               "    \"Locking Enabled\": %i,\n"
               "    \"Locking Supported\": %i\n"
               "  }",
               body->shared.descriptor_version, body->hw_reset_for_lor_dor_supported, body->mbr_shadowing_not_supported,
               body->MBR_done, body->MBR_enabled, body->media_encryption, body->locked, body->locking_enabled,
               body->locking_supported);
    }

    if (dev->features.geometry.shared.feature_code) {
        struct level_0_discovery_geometry_feature *body = &dev->features.geometry;

        print_comma_start(&first);
        printf("  \"Geometry Feature\": {\n"
               "    \"Version\": %i,\n"
               "    \"ALIGN\": %i,\n"
               "    \"LogicalBlockSize\": %i,\n"
               "    \"AlignmentGranularity\": %li,\n"
               "    \"LowestAlignedLBA\": %li\n"
               "  }",
               body->shared.descriptor_version, body->align, be32_to_cpu(body->logical_block_size),
               be64_to_cpu(body->alignment_granularity), be64_to_cpu(body->lowest_alignment_LBA));
    }

    if (dev->features.opal2.shared.feature_code) {
        struct level_0_discovery_opal_2_feature *body = &dev->features.opal2;

        print_comma_start(&first);
        printf("  \"Opal SSC V2.00 Feature\": {\n"
               "    \"Feature Descriptor Version Number\": %i,\n"
               "    \"SSC Minor Version Number\": %i,\n"
               "    \"Base ComID\": %i,\n"
               "    \"Number of ComIDs\": %i,\n"
               "    \"Range Crossing Behavior\": %i,\n"
               "    \"Number of Locking SP Admin Authorities Supported\": %i,\n"
               "    \"Number of Locking SP User Authorities Supported\": %i,\n"
               "    \"Initial C_PIN_SID PIN Indicator\": %i,\n"
               "    \"Behavior of C_PIN_SID PIN upon TPer Revert\": %i\n"
               "  }",
               body->shared.descriptor_version, body->shared.reserved, be16_to_cpu(body->base_comID),
               be16_to_cpu(body->number_of_comIDs), body->range_crossing_behaviour,
               be16_to_cpu(body->number_of_locking_admin_authorities_supported),
               be16_to_cpu(body->number_of_locking_user_authorities_supported), body->initial_pin_indicator,
               body->behavior_of_pin_upon_revert);
    }

    if (dev->features.opal1.shared.feature_code) {
        struct level_0_discovery_opal_1_feature *body = &dev->features.opal1;

        print_comma_start(&first);
        printf("  \"Opal SSC V1.00 Feature Descriptor\": {\n"
               "    \"Version\": %i,\n"
               "    \"Base ComID\": %i,\n"
               "    \"Number of ComIDs\": %i,\n"
               "    \"Range Crossing\": %i\n"
               "  }",
               body->shared.descriptor_version, be16_to_cpu(body->base_comID),
               be16_to_cpu(body->number_of_comIDs), body->range_crossing);
    } else if (dev->features.single_user_mode.shared.feature_code) {
        struct level_0_discovery_single_user_mode_feature *body = &dev->features.single_user_mode;

        print_comma_start(&first);
        printf("  \"Single User Mode Feature\": {\n"
               "    \"Version\": %i,\n"
               "    \"Number of Locking Objects Supported\": %i,\n"
               "    \"Policy\": %i,\n"
               "    \"All\": %i,\n"
               "    \"Any\": %i\n"
               "  }",
               body->shared.descriptor_version, be32_to_cpu(body->number_of_locking_objects_supported), body->policy,
               body->all, body->any);
    }

    if (dev->features.data_store.shared.feature_code) {
        struct level_0_discovery_data_store_feature *body = &dev->features.data_store;

        print_comma_start(&first);
        printf("  \"DataStore Table Feature\": {\n"
               "    \"Version\": %i,\n"
               "    \"Maximum number of DataStore tables\": %i,\n"
               "    \"Maximum total size of DataStore tables\": %i,\n"
               "    \"DataStore table size alignment\": %i\n"
               "  }",
               body->shared.descriptor_version, be16_to_cpu(body->maximum_number_of_tables),
               be32_to_cpu(body->maximum_total_size_of_tables), be32_to_cpu(body->table_size_alignment));
    }

    if (dev->features.block_sid_authentication.shared.feature_code) {
        struct level_0_discovery_block_sid_authentication_feature *body = &dev->features.block_sid_authentication;

        print_comma_start(&first);
        printf("  \"Block SID Authentication Feature\": {\n"
               "    \"Version\": %i,\n"
               "    \"Locking SP Freeze Lock State \": %i,\n"
               "    \"Locking SP Freeze Lock supported\": %i,\n"
               "    \"SID Authentication Blocked State\": %i,\n"
               "    \"SID Value State\": %i,\n"
               "    \"Hardware Reset\": %i\n"
               "  }",
               body->shared.descriptor_version, body->locking_sp_freeze_lock_state,
               body->locking_sp_freeze_lock_supported, body->sid_authentication_blocked_state, body->sid_value_state,
               body->hardware_reset);
    }

    if (dev->features.pyrite.shared.feature_code) {
        struct level_0_discovery_pyrite_feature *body = &dev->features.pyrite;

        print_comma_start(&first);
        printf("  \"Pyrite SSC Feature Descriptor\": {\n"
               "    \"Version\": %i,\n"
               "    \"Base ComID\": %i,\n"
               "    \"Number of ComIDs\": %i,\n"
               "    \"Initial C_PIN_SID PIN Indicator\": %i,\n"
               "    \"Behavior of C_PIN_SID PIN upon TPer Revert\": %i\n"
               "  }",
               body->shared.descriptor_version, be16_to_cpu(body->base_comID),
               be16_to_cpu(body->number_of_comIDs), body->initial_pin_indicator, body->behavior_of_pin_upon_revert);
    }

    if (dev->features.supported_data_removal_mechanism.shared.feature_code) {
        struct level_0_discovery_supported_data_removal_mechanism_feature *body =
                &dev->features.supported_data_removal_mechanism;

        print_comma_start(&first);
        printf("  \"Supported Data Removal Mechanism Feature Descriptor\": {\n"
               "    \"Version\": %i,\n"
               "    \"Data Removal Operation Processing\": %i,\n"
               "    \"Supported Data Removal Mechanism\": %i,\n"
               "    \"Data Removal Time Format for Bit 0\": %i,\n"
               "    \"Data Removal Time Format for Bit 1\": %i,\n"
               "    \"Data Removal Time Format for Bit 2\": %i,\n"
               "    \"Data Removal Time Format for Bit 3\": %i,\n"
               "    \"Data Removal Time Format for Bit 4\": %i,\n"
               "    \"Data Removal Time Format for Bit 5\": %i,\n"
               "    \"Data Removal Time for Supported Data Removal Mechanism Bit 0\": %i,\n"
               "    \"Data Removal Time for Supported Data Removal Mechanism Bit 1\": %i,\n"
               "    \"Data Removal Time for Supported Data Removal Mechanism Bit 2\": %i,\n"
               "    \"Data Removal Time for Supported Data Removal Mechanism Bit 3\": %i,\n"
               "    \"Data Removal Time for Supported Data Removal Mechanism Bit 4\": %i,\n"
               "    \"Data Removal Time for Supported Data Removal Mechanism Bit 5\": %i\n"
               "  }",
               body->shared.descriptor_version, body->data_removal_operation_processing,
               body->supported_data_removal_mechanism,
               !!(body->data_removal_time_format & (1 << 0)), !!(body->data_removal_time_format & (1 << 1)),
               !!(body->data_removal_time_format & (1 << 2)), !!(body->data_removal_time_format & (1 << 3)),
               !!(body->data_removal_time_format & (1 << 4)), !!(body->data_removal_time_format & (1 << 5)),
               be16_to_cpu(body->data_removal_time_for_supported_data_removal_mechanism[0]),
               be16_to_cpu(body->data_removal_time_for_supported_data_removal_mechanism[1]),
               be16_to_cpu(body->data_removal_time_for_supported_data_removal_mechanism[2]),
               be16_to_cpu(body->data_removal_time_for_supported_data_removal_mechanism[3]),
               be16_to_cpu(body->data_removal_time_for_supported_data_removal_mechanism[4]),
               be16_to_cpu(body->data_removal_time_for_supported_data_removal_mechanism[5]));
    }

    for (size_t i = 0; i < dev->features.unknown_len;) {
        struct level_0_discovery_feature_shared *header =
                (struct level_0_discovery_feature_shared *)(dev->features.unknown + i);
        size_t body_len = header->length + 4;

        print_comma_start(&first);
        printf("  \"0x%x\": { \"data\": 0x", header->feature_code);
        for (size_t j = 0; j < body_len; ++j) {
            printf("%02x", ((unsigned char *)header)[j]);
        }
        printf("\" }");

        i += body_len;
    }
}

static size_t parse_and_print(unsigned char *response, size_t *i, int ascii_only)
{
    size_t len = 0;
    size_t bytes_flag = 0;

    if ((response[*i] & 0b10000000) == 0b00000000) {
        // tiny atom
        len = 0;
    } else if ((response[*i] & 0b11000000) == 0b10000000) {
        // short atom
        len = (response[*i] & 0b00001111);
        bytes_flag = response[*i] & 0b00100000;
    } else if ((response[*i] & 0b11100000) == 0b11000000) {
        // medium atom
        len = ((response[*i] & 0b00000111) << 8) | (response[*i + 1]);
        bytes_flag = response[*i] & 0b00010000;
        *i += 1;
    } else if (((response[*i] & 0b11110000) == 0b11100000)) {
        // long atom
        len = (response[*i] << 16) | (response[*i + 1] << 8) | (response[*i + 2]);
        bytes_flag = response[*i] & 0b00001000;
        *i += 2;
    } else {
        return 1;
    }

    if (ascii_only == 1) {
        if (len == 0) {
            printf("%c", response[*i] & 0b00111111);
        } else {
            size_t off = 0;
            for (; off < len; ++off) {
                printf("%c", response[*i + off + 1]);
            }
            *i += off;
        }
    } else {
        if (bytes_flag) {
            int ascii = 1;

            size_t off = 0;
            for (; off < len; ++off) {
                if (response[*i + off + 1] < ' ' || response[*i + off + 1] > '~') {
                    ascii = 0;
                    break;
                }
            }

            off = 0;
            if (ascii) {
                printf("(");
                for (; off < len; ++off) {
                    printf("%c", response[*i + off + 1]);
                }
                printf(") ");
            }
        }

        if (len == 0) {
            printf("0x%02x", response[*i] & 0b00111111);
        } else {
            size_t off = 0;
            printf("0x");
            for (; off < len; ++off) {
                printf("%02x", response[*i + off + 1]);
            }
            *i += off;
        }
    }

    *i += 1;

    return 0;
}

typedef void (*crawl_cb_t)(unsigned char *buffer, size_t buffer_len, void *data);

static int print_properties(struct disk_device *dev)
{
    int err = 0;

    LOG(INFO, "Get properties:\n");
    unsigned char command[2048] = { 0 };
    unsigned char response[2048] = { 0 };
    size_t cmd_len = 0;

    // No session needed for SMUID method -> just get ComID.
    if ((err = do_level_0_discovery(dev))) {
        LOG(ERROR, "Failed to get ComID.\n");
        return err;
    }

    LOG(INFO, "Sending Parameters:\n");
    /*
    SMUID.Properties[ HostProperties = list [ name = value ... ] ]
    =>
    SMUID.Properties[ Properties : list [ name = value ... ], HostProperties = list [ name = value ... ] ]
    */
    prepare_method(command, &cmd_len, dev, SMUID, METHOD_PROPERTIES_UID);
    finish_method(command, &cmd_len);
    if ((err = invoke_method(dev, command, cmd_len, response, sizeof(response)))) {
        LOG(ERROR, "Failed to get communication parameters.\n");
        return err;
    }

    size_t i = 0;
    err = skip_to_parameter(response, &i, 0, 0);
    if (err || response[i++] != START_LIST_TOKEN) {
        return 1;
    }

    printf("  \"Properties\": {\n");

    int first_entry = 0;
    while (i < sizeof(response)) {
        if (response[i] == END_LIST_TOKEN) {
            break;
        }

        if (response[i++] != START_NAME_TOKEN) {
            return 1;
        }

        print_comma_start(&first_entry);
        printf("    \"");
        parse_and_print(response, &i, 1);
        printf("\": \"");
        parse_and_print(response, &i, 0);
        printf("\"");

        if (response[i++] != END_NAME_TOKEN) {
            return 1;
        }
    }
    printf("\n  }\n");

    return err;
}

#define from_hex(c) (isdigit(c) ? c - '0' : tolower(c) - 'a' + 10)
static void unhexmangle_string(char *txt)
{
    size_t sz = 0, len;
    char *buf = txt;

    len = strlen(buf);
    if (!len)
        return;

    while(*txt && sz < len) {
        if (*txt == '\\' && sz + 3 < len && txt[1] == 'x' &&
            isxdigit(txt[2]) && isxdigit(txt[3])) {

            *buf++ = from_hex(txt[2]) << 4 | from_hex(txt[3]);
            txt += 4;
            sz += 4;
        } else {
            *buf++ = *txt++;
            sz++;
        }
    }
    *buf = '\0';
}

static void normalize_whitespace(char *txt)
{
    size_t sz, i, x = 0;
    int nsp = 0, intext = 0;

    sz = strlen(txt);

    for (i = 0, x = 0; i < sz && x < sz;) {
        if (isspace(txt[i]))
            nsp++;
        else
            nsp = 0, intext = 1;

        if (nsp > 1 || (nsp && !intext))
            i++;
        else
            txt[x++] = txt[i++];
    }
    if (nsp && x > 0)
        x--;

    txt[x] = '\0';
}

static int print_property(struct udev_device *dev, const char *prop, const char *desc)
{
    const char *data = udev_device_get_property_value(dev, prop);
    char *p;

    if (!data)
        return 1;

    p = strdup(data);
    if (!p)
        return 1;

    if (!strcmp(prop, "ID_MODEL_ENC") || !strcmp(prop, "ID_VENDOR_ENC"))
        unhexmangle_string(p);
    normalize_whitespace(p);
    printf("  \"%s\": \"%s\",\n", desc, p);
    free(p);

    return 0;
}

static int print_udev_identify(const char *name)
{
    struct udev *udev;
    struct udev_device *dev;

    udev = udev_new();
    if (!udev)
        return -ENODEV;

    dev = udev_device_new_from_subsystem_sysname(udev, "block", name);
    if (!dev) {
        udev_unref(udev);
        return -ENODEV;
    }

    print_property(dev, "ID_SERIAL_SHORT", "Serial number");
    print_property(dev, "ID_REVISION", "Firmware version");
    if (print_property(dev, "ID_MODEL_ENC", "Model number"))
        print_property(dev, "ID_MODEL", "Model number");
    if (print_property(dev, "ID_VENDOR_ENC", "Vendor"))
        print_property(dev, "ID_VENDOR", "Vendor");
    print_property(dev, "ID_SERIAL", "Serial number long");

    udev_device_unref(dev);
    udev_unref(udev);

    return 0;
}

typedef void (*crawl_cb_t)(unsigned char *buffer, size_t buffer_len, void *data);

/**
 * Callback to print the iterated rows.
 */
static void crawl_cb_print_row(unsigned char *response, size_t last, void *data)
{
    (void)data;

    size_t i = 0;

    if (response[i++] != START_LIST_TOKEN) {
        LOG(ERROR, "Unexpected token.\n");
    }
    if (response[i] == END_LIST_TOKEN) {
        i += 1;
        return;
    }
    if (response[i++] != START_LIST_TOKEN) {
        LOG(ERROR, "Unexpected token.\n");
    }

    int first = 0;
    while (i < last) {
        if (response[i] == END_LIST_TOKEN) {
            if (response[i + 0] != END_LIST_TOKEN || response[i + 1] != END_LIST_TOKEN) {
                LOG(ERROR, "Unexpected token.\n");
            }
            i += 2;
            break;
        }
        if (response[i++] != START_NAME_TOKEN) {
            LOG(ERROR, "Unexpected token.\n");
        }
        print_comma_start(&first);
        printf("        \"");
        parse_and_print(response, &i, 0);
        printf("\": \"");

        if (parse_and_print(response, &i, 0)) {
            if (response[i] != START_LIST_TOKEN)
                printf("0x");
            int depth = 0;
            do {
                if (response[i] == START_LIST_TOKEN) {
                    if (depth == 0)
                        printf("[");
                    depth += 1;
                    i += 1;
                } else if (response[i] == END_LIST_TOKEN) {
                    depth -= 1;
                    if (depth == 0)
                        printf("]");
                    i += 1;
                } else {
                    printf("%02x", response[i]);
                    i += 1;
                }
            } while (depth > 0 && i < last);
        }
        printf("\"");
        if (response[i++] != END_NAME_TOKEN) {
            LOG(ERROR, "Unexpected token.\n");
        }
    }

    printf("\n");
}

/**
 * Callback to remember the iterated rows.
 */
struct crawl_cb_save_row_data {
    int count;
    unsigned char data[2048];
    uint64_t column;
};
static void crawl_cb_save_row(unsigned char *response, size_t last, void *data)
{
    /*
    [ Result : RowValues : list [ ColumnNumber = Value ... ] ]
    */
    struct crawl_cb_save_row_data *collector = data;

    if (response[0] != START_LIST_TOKEN || response[1] != START_LIST_TOKEN) {
        LOG(ERROR, "Found unexpected token.\n");
    }
    for (size_t i = 2; i < last; ++i) {
        if (response[i] == END_LIST_TOKEN) {
            return;
        } else if (response[i] == START_NAME_TOKEN) {
            i += 1;

            uint64_t column = parse_int(response, &i);
            if (column == collector->column) {
                parse_bytes(response, &i, collector->data + 8 * collector->count, 8, NULL);
                collector->count += 1;

                return;
            }

            skip_atom(response, &i, last);
            if (response[i] != END_NAME_TOKEN) {
                LOG(ERROR, "Found unexpected token.\n");
            }
        } else {
            LOG(ERROR, "Found unexpected token.\n");
        }
    }
}

static int crawl_table_row(struct disk_device *dev, unsigned char *uidref, crawl_cb_t cb, void *cb_data)
{
    int err = 0;

    unsigned char buffer[2048] = { 0 };
    size_t i = 0;
    unsigned char response[2048] = { 0 };


    prepare_method(buffer, &i, dev, uidref, METHOD_GET_UID);
    start_list(buffer, &i);
    end_list(buffer, &i);
    finish_method(buffer, &i);

    if ((err = invoke_method(dev, buffer, i, response, sizeof(response)))) {
        LOG(ERROR, "Failed to acquire content of row.\n");
        return err;
    }

    struct packet_headers *header = (struct packet_headers *)response;
    uint32_t last = be32_to_cpu(header->data_subpacket.length);

    cb(response + sizeof(struct packet_headers), last, cb_data);

    return err;
}

static int crawl_table(struct disk_device *dev, const unsigned char *table_uid, crawl_cb_t cb, void *cb_data,
                       int printing)
{
    size_t i = 0;
    int err = 0;

    LOG(INFO, "Getting Table Table:\n");
    unsigned char buffer[2048] = { 0 };
    unsigned char response[2048] = { 0 };

    LOG(INFO, "Sending Next:\n");
    /*
    TableUID.Next [
    Where = uidref,
    Count = uinteger ]
    =>
    [ Result : list [ uidref ... ] ]
    */
    prepare_method(buffer, &i, dev, table_uid, METHOD_NEXT_UID);
    finish_method(buffer, &i);
    if ((err = invoke_method(dev, buffer, i, response, sizeof(response)))) {
        return err;
    }

    skip_to_parameter(response, &i, 0, 0);
    if (response[i++] != START_LIST_TOKEN) {
        return 1;
    }

    int first = 0;
    while (i < sizeof(response)) {
        if (response[i++] != 0xa8) {
            break;
        }

        if (printing) {
            print_comma_start(&first);
            print_uid_key(response + i, 6, 1);
        }
        crawl_table_row(dev, response + i, cb, cb_data);
        if (printing) {
            printf("      }");
        }

        i += 8;
    }

    if (printing) {
        printf("\n");
    }

    return err;
}

static int crawl_tper(struct disk_device *dev)
{
    int err = 0;

    // In general:
    // 1. Get Admin SP's SP table.
    // 2. For every SP get Table table.
    // 3. For every table iterate all rows.

    struct crawl_cb_save_row_data rows_of_sp_table = { .column = 0 };

    // Find all SPs from Admin SP's SP table.
    if ((err = start_session(dev, ADMIN_SP_UID, ANYBODY_USER_ID, NULL, 0))) {
        LOG(ERROR, "Failed to initialise session with Admin SP as Anybody.\n");
        return err;
    }
    if ((err = crawl_table(dev, TABLE_SP_UID, crawl_cb_save_row, &rows_of_sp_table, 0))) {
        LOG(ERROR, "Failed to crawl Admin SP's Table table\n");
        close_session(dev);
        return err;
    }
    if ((err = close_session(dev))) {
        LOG(ERROR, "Failed to close session with Admin SP.\n");
        return err;
    }

    for (int i = 0; i < rows_of_sp_table.count; ++i) {
        struct crawl_cb_save_row_data rows_of_table_table = { .column = 0 };
        unsigned char *current_sp = rows_of_sp_table.data + i * 8;

        print_uid_key(current_sp, 2, i == 0);

        // Find all tables from the SP's Table table.
        if ((err = start_session(dev, current_sp, ANYBODY_USER_ID, NULL, 0))) {
            LOG(ERROR, "Failed to initialise session with SP %i as Anybody.\n", i);
            printf("    }");
            continue;
        }
        if ((err = crawl_table(dev, TABLE_TABLE_UID, crawl_cb_save_row, &rows_of_table_table, 0))) {
            close_session(dev);
            LOG(ERROR, "Failed to crawl SP %i's Table table.\n", i);
            printf("    }");
            continue;
        }
        if ((err = close_session(dev))) {
            LOG(ERROR, "Failed to close session with SP %i.\n", i);
            printf("    }");
            continue;
        }

        // Iterate tables found in the SP.
        for (int j = 0; j < rows_of_table_table.count; ++j) {
            unsigned char *current_table = rows_of_table_table.data + j * 8;
            // Upper 4 bytes are table specific, lower 4 bytes represent the object.
            // Shift the bytes to left, so we have table that the object represents.
            current_table[0] = current_table[4];
            current_table[1] = current_table[5];
            current_table[2] = current_table[6];
            current_table[3] = current_table[7];
            current_table[4] = current_table[5] = current_table[6] = current_table[7] = 0;

            print_uid_key(current_table, 4, j == 0);

            if ((err = start_session(dev, current_sp, ANYBODY_USER_ID, NULL, 0))) {
                LOG(ERROR, "Failed to initialise session with SP %i as Anybody.\n", i);
                printf("    }");
                continue;
            }
            if ((err = crawl_table(dev, current_table, crawl_cb_print_row, NULL, 1))) {
                LOG(INFO, "Cannot iterate table. Going to print only the first row instead.\n");

                // Try row XX XX XX XX 00 00 00 01 (e.g. SPInfoObj).
                unsigned char row_uid[8] = { 0 };
                memcpy(row_uid, current_table, 8);
                row_uid[7] = 0x01;

                print_uid_key(row_uid, 6, 1);
                if ((err = crawl_table_row(dev, row_uid, crawl_cb_print_row, NULL))) {
                    printf("        \"error\": \"%s (%i)\"\n", error_to_string(err), err);
                }
                printf("      },\n");

                // Try row XX XX XX XX 00 03 00 01 (e.g. TPerInfoObj).
                row_uid[5] = 0x03;

                print_uid_key(row_uid, 6, 1);
                if ((err = crawl_table_row(dev, row_uid, crawl_cb_print_row, NULL))) {
                    printf("        \"error\": \"%s (%i)\"\n", error_to_string(err), err);
                }
                printf("      }\n");
            }
            if ((err = close_session(dev))) {
                LOG(ERROR, "Failed to close a session.\n");
            }
            printf("    }");
        }
        printf("\n  }");
    }
    printf("\n");

    return err;
}

static int print_single_row(struct disk_device *dev, const unsigned char *table_uid, const unsigned char *sp_uid)
{
    int err = 0;

    unsigned char buffer[2048] = { 0 };
    size_t i = 0;
    unsigned char response[2048] = { 0 };

    if ((err = start_session(dev, sp_uid, ANYBODY_USER_ID, NULL, 0))) {
        LOG(ERROR, "failed to initialize session\n");
        return err;
    }

    prepare_method(buffer, &i, dev, table_uid, METHOD_GET_UID);
    start_list(buffer, &i);
    end_list(buffer, &i);
    finish_method(buffer, &i);

    if ((err = invoke_method(dev, buffer, i, response, sizeof(response)))) {
        LOG(ERROR, "Failed to acquire content of row.\n");
        close_session(dev);
        return err;
    }

    struct packet_headers *header = (struct packet_headers *)response;
    uint32_t last = be32_to_cpu(header->data_subpacket.length);

    crawl_cb_print_row(response + sizeof(struct packet_headers), last, NULL);

    if ((err = close_session(dev))) {
        LOG(ERROR, "failed to close a session\n");
        return err;
    }

    return err;
}

static int print_discovery(struct disk_device *dev, int selection)
{
    int err = 0;
    int first = 0;

    printf("{\n");

    print_comma_start(&first);
    printf("\"Metadata\": {\n"
           "  \"Version\": \"%i\"\n"
           "}",
           TOOL_VERSION);

    print_comma_start(&first);
    printf("\"Identify\": {\n");
    err = print_udev_identify(dev->name);
    printf("}");

    if ((selection == SELECT_EVERYTHING) || (selection == SELECT_DISCOVERY_0)) {
        print_comma_start(&first);
        printf("\"Discovery 0\": {\n");
        err = do_level_0_discovery(dev);
        if (!err) {
            print_level_0_discovery(dev);
        }
        printf("}");
    }

    if ((selection == SELECT_EVERYTHING) || (selection == SELECT_DISCOVERY_1)) {
        print_comma_start(&first);
        printf("\"Discovery 1\": {\n");
        err = print_properties(dev);
        printf("}");
    }

    if ((selection == SELECT_EVERYTHING) || (selection == SELECT_DISCOVERY_2)) {
        print_comma_start(&first);
        printf("\"Discovery 2\": {\n");
        err = crawl_tper(dev);
        printf("}");
    }

    if ((selection == SELECT_EVERYTHING) || (selection == SELECT_DISCOVERY_2_EXTRA)) {
        const unsigned char *manual_discovery_list[] = {
            TABLE_TPER_INFO_OBJ_UID,
            DATA_REMOVAL_MECHANISM_OBJ_UID,
        };
        const size_t list_size = sizeof(manual_discovery_list) / sizeof(unsigned char *);

        print_comma_start(&first);
        printf("\"Discovery 2 manual\": {\n");
        for (size_t entry = 0; entry < list_size; ++entry) {
            printf("  \"0x");
            for (int i = 0; i < 8; ++i) {
                printf("%02x", manual_discovery_list[entry][i]);
            }
            printf("\": {\n");
            if ((err = print_single_row(dev, manual_discovery_list[entry], ADMIN_SP_UID))) {
                printf("    \"error\": \"%s\"\n", error_to_string(err));
            }
            printf("  }%s\n", entry == (list_size - 1) ? "" : ",");
        }
        printf("}");
    }

    if (((selection == SELECT_EVERYTHING)) || ((selection == SELECT_RNG))) {
        print_comma_start(&first);
        printf("\"Random sample\": [\n");
        for (int i = 0; i < 4; ++i) {
            unsigned char random[128] = { 0 };

            if ((err = get_random(dev, random, sizeof(random)))) {
                printf("  \"error\": \"%s\"", error_to_string(err));
                break;
            }
            printf("%s  [\n", i == 0 ? "" : ",\n");
            for (int j = 0; j < 4; ++j) {
                printf("%s    \"", j == 0 ? "" : ",\n");
                for (int k = 0; k < 32; ++k) {
                    printf("%02x", random[j * 32 + k]);
                }
                printf("\"");
            }
            printf("\n  ]");
        }
        printf("\n]\n");
    }
    printf("}\n");

    return err;
}

static void print_usage(char *prog_name)
{
    fprintf(stderr,
            "Usage: %s <device> [selection [log_level]] [--scsi]\n"
            "\n"
            "selection: 0=everything,\n"
            "           1=metainformation,\n"
            "           2=identify,\n"
            "           3=level 0 discovery,\n"
            "           4=level 1 discovery,\n"
            "           5=level 2 discovery,\n"
            "           6=level 2 discovery - extra,\n"
            "           7=rng\n"
            "log:       0=error,\n"
            "           1=info,\n"
            "           2=everything\n"
            "--scsi:    use SCSI security protocol command\n"
            "\n",
            prog_name);
    exit(1);
}

int main(int argc, char **argv)
{
    int err = 0;
    const char *dev_file = NULL;
    int selection = 0;
    bool use_scsi_sec = false;

    if (argc > 2 && !strcmp(argv[argc - 1], "--scsi")) {
        use_scsi_sec = true;
        argc--;
    }

    switch (argc) {
    case 4:
        current_log_level = atoi(argv[3]);
        if (current_log_level < ERROR || current_log_level > EVERYTHING) {
            print_usage(argv[0]);
        }
        // fallthrough
    case 3:
        selection = atoi(argv[2]);
        if (selection > 7) {
            print_usage(argv[0]);
        }
        // fallthrough
    case 2:
        if (argv[1][0] == '-') {
            print_usage(argv[0]);
        }
        dev_file = argv[1];
        break;
    default:
        print_usage(argv[0]);
    }

    struct disk_device dev = { 0 };
    if ((err = disk_device_open(&dev, dev_file, use_scsi_sec))) {
        return err;
    }

    err = print_discovery(&dev, selection);

    disk_device_close(&dev);

    return err;
}
