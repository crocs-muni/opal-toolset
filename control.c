// SPDX-License-Identifier: MIT

#include "common.h"
#include "utils.h"
#include <argp.h>

#define MAIN_DOC_STRING                                                                                                \
    "        device               Opal-compliant device\n" \
    "        command              One of the commands defined further\n"

#define PIN_MAX_LEN 512

enum ArgKey {
    ARG_KEY_VERIFY_PIN = 'v',
    ARG_KEY_VERIFY_PIN_HEX = 9,
    ARG_KEY_ASSIGN_PIN = 1,
    ARG_KEY_ASSIGN_PIN_HEX = 8,
    ARG_KEY_USER = 'u',
    ARG_KEY_ADMIN = 'a',
    ARG_KEY_LOCKING_RANGE = 'l',
    ARG_KEY_LOCKING_RANGE_START = 7,
    ARG_KEY_LOCKING_RANGE_LENGTH = 6,
    ARG_KEY_READ_LOCK_ENABLED = 2,
    ARG_KEY_WRITE_LOCK_ENABLED = 3,
    ARG_KEY_READ_LOCKED = 4,
    ARG_KEY_WRITE_LOCKED = 5,
    ARG_KEY_VERBOSE = 'V',
    ARG_KEY_SCSI = 'S',
    ARG_KEY_SUM = 10,
    ARG_KEY_SUM_RANGE_ADMIN = 11,
};

static struct argp_option options_setup_range[] = {
    { "verify-pin", ARG_KEY_VERIFY_PIN, "pin", 0, "Password of Admin1 authority", 0 },
    { "verify-pin-hex", ARG_KEY_VERIFY_PIN_HEX, "hex_pin", 0, "Password of Admin1 authority", 0 },
    { "user", ARG_KEY_USER, "id", 0, "User to have control over the locking range (can be repeated)", 0 },
    { "locking-range", ARG_KEY_LOCKING_RANGE, "id", 0, "Locking range to change", 0 },
    { "locking-range-start", ARG_KEY_LOCKING_RANGE_START, "position", 0, NULL, 0 },
    { "locking-range-length", ARG_KEY_LOCKING_RANGE_LENGTH, "length", 0, NULL, 0 },
    { 0 }
};

static struct argp_option options_list_range[] = {
    { "verify-pin", ARG_KEY_VERIFY_PIN, "pin", 0, "Password of user authority", 0 },
    { "verify-pin-hex", ARG_KEY_VERIFY_PIN_HEX, "hex_pin", 0, "Password of user authority", 0 },
    { "user", ARG_KEY_USER, "id", 0, "User authority id", 0 },
    { "admin", ARG_KEY_ADMIN, "id", 0, "Admin authority to authenticate as", 0 },
    { "locking-range", ARG_KEY_LOCKING_RANGE, "id", 0, "Locking range to list", 0 },
    { 0 }
};

static struct argp_option options_setup_user[] = {
    { "verify-pin", ARG_KEY_VERIFY_PIN, "pin", 0, "Password of Admin1 authority", 0 },
    { "verify-pin-hex", ARG_KEY_VERIFY_PIN_HEX, "hex_pin", 0, "Password of Admin1 authority", 0 },
    { "assign-pin", ARG_KEY_ASSIGN_PIN, "pin", 0, "Password to assign to selected user authority", 0 },
    { "assign-pin-hex", ARG_KEY_ASSIGN_PIN_HEX, "hex_pin", 0, "Password to assign to selected user authority", 0 },
    { "user", ARG_KEY_USER, "id", 0, "ID of the user authority", 0 },
    { "sum", ARG_KEY_SUM, NULL, 0, "Use Single User Mode (SUM)", 0 },
    { "locking-range", ARG_KEY_LOCKING_RANGE, "id", 0, "SUM locking range", 0 },
    { 0 }
};

static struct argp_option options_setup_password[] = {
    { "verify-pin", ARG_KEY_VERIFY_PIN, "pin", 0, "Password of the authority (first user or admin option)", 0 },
    { "verify-pin-hex", ARG_KEY_VERIFY_PIN_HEX, "hex_pin", 0, "Password of the authority (first user or admin option)", 0 },
    { "assign-pin", ARG_KEY_ASSIGN_PIN, "pin", 0, "Password to set (second user or admin option)", 0 },
    { "assign-pin-hex", ARG_KEY_ASSIGN_PIN_HEX, "hex_pin", 0, "Password to ser (second user or admin option)", 0 },
    { "user", ARG_KEY_USER, "id", 0, "ID of the user authority", 0 },
    { "admin", ARG_KEY_ADMIN, "id", 0, "ID of the admin authority", 0 },
    { 0 }
};

static struct argp_option options_setup_tper[] = { 
    { "assign-pin", ARG_KEY_ASSIGN_PIN, "pin", 0, "Password to assign to the owner authority", 0 },
    { "assign-pin-hex", ARG_KEY_ASSIGN_PIN_HEX, "hex_pin", 0, "Password to assign to the owner authority", 0 },
    { "sum", ARG_KEY_SUM, NULL, 0, "Use Single User Mode (SUM)", 0 },
    { "sum-policy", ARG_KEY_SUM_RANGE_ADMIN, NULL, 0, "Use SUM policy Admin only", 0 },
    { "locking-range", ARG_KEY_LOCKING_RANGE, "id", 0, "SUM locking range (default is whole table)", 0 },
    { 0 }
};

static struct argp_option options_psid_revert[] = { 
    { "verify-pin", ARG_KEY_VERIFY_PIN, "pin", 0, "PSID", 0 },
    { "verify-pin-hex", ARG_KEY_VERIFY_PIN_HEX, "hex_pin", 0, "PSID", 0 },
    { 0 } 
};

static struct argp_option options_regenerate_key[] = {
    { "verify-pin", ARG_KEY_VERIFY_PIN, "pin", 0, "Password of the authority", 0 },
    { "verify-pin-hex", ARG_KEY_VERIFY_PIN_HEX, "hex_pin", 0, "Password of the authority", 0 },
    { "user", ARG_KEY_USER, "id", 0, "User authority to authenticate as", 0 },
    { "admin", ARG_KEY_ADMIN, "id", 0, "Admin authority to authenticate as", 0 },
    { "locking-range", ARG_KEY_LOCKING_RANGE, "id", 0, "Locking range to re-generate", 0 },
    { 0 }
};

static struct argp_option options_erase_range[] = {
    { "verify-pin", ARG_KEY_VERIFY_PIN, "pin", 0, "Password of Admin1 authority", 0 },
    { "verify-pin-hex", ARG_KEY_VERIFY_PIN_HEX, "hex_pin", 0, "Password of Admin1 authority", 0 },
    { "locking-range", ARG_KEY_LOCKING_RANGE, "id", 0, "Locking range to re-generate", 0 },
    { 0 }
};

static struct argp_option options_unlock[] = {
    { "verify-pin", ARG_KEY_VERIFY_PIN, "pin", 0, "Password of the authority", 0 },
    { "verify-pin-hex", ARG_KEY_VERIFY_PIN_HEX, "hex_pin", 0, "Password of the authority", 0 },
    { "user", ARG_KEY_USER, "id", 0, "User authority to authenticate as", 0 },
    { "admin", ARG_KEY_ADMIN, "id", 0, "Admin authority to authenticate as", 0 },
    { "locking-range", ARG_KEY_LOCKING_RANGE, "id", 0, "Locking range to lock/unlock", 0 },
    { "read-locked", ARG_KEY_READ_LOCKED, "state", 0, NULL, 0 },
    { "write-locked", ARG_KEY_WRITE_LOCKED, "state", 0, NULL, 0 },
    { 0 }
};

static struct argp_option options_setup_enable_range[] = {
    { "verify-pin", ARG_KEY_VERIFY_PIN, "pin", 0, "Password of the authority", 0 },
    { "verify-pin-hex", ARG_KEY_VERIFY_PIN_HEX, "hex_pin", 0, "Password of the authority", 0 },
    { "user", ARG_KEY_USER, "id", 0, "User authority to authenticate as", 0 },
    { "admin", ARG_KEY_ADMIN, "id", 0, "Admin authority to authenticate as", 0 },
    { "locking-range", ARG_KEY_LOCKING_RANGE, "id", 0, "Locking range to lock/unlock", 0 },
    { "read-lock-enabled", ARG_KEY_READ_LOCK_ENABLED, "state", 0, NULL, 0 },
    { "write-lock-enabled", ARG_KEY_WRITE_LOCK_ENABLED, "state", 0, NULL, 0 },
    { 0 }
};

static struct argp_option options_setup_reactivate[] = {
    { "verify-pin", ARG_KEY_VERIFY_PIN, "pin", 0, "Password of the authority", 0 },
    { "verify-pin-hex", ARG_KEY_VERIFY_PIN_HEX, "hex_pin", 0, "Password of the authority", 0 },
    { "admin", ARG_KEY_ADMIN, "id", 0, "Admin authority to authenticate as", 0 },
    { "sum", ARG_KEY_SUM, NULL, 0, "Use Single User Mode (SUM)", 0 },
    { "sum-policy", ARG_KEY_SUM_RANGE_ADMIN, NULL, 0, "Use SUM policy Admin only", 0 },
    { "locking-range", ARG_KEY_LOCKING_RANGE, "id", 0, "SUM locking range (default is whole table)", 0 },
    { 0 }
};

static struct argp_option options_reset[] = { 
    { "No options", 0, "NULL", OPTION_DOC},
    { 0 }
};

static struct argp_option options_stack_reset[] = {
    { "No options", 0, "NULL", OPTION_DOC},
    { 0 }
};

static struct argp_option options_setup_reset[] = {
    { "verify-pin", ARG_KEY_VERIFY_PIN, "pin", 0, "Password of Admin1 authority", 0 },
    { "verify-pin-hex", ARG_KEY_VERIFY_PIN_HEX, "hex_pin", 0, "Password of Admin1 authority", 0 },
    { "locking-range", ARG_KEY_LOCKING_RANGE, "id", 0, "Locking range to enable reset", 0 },
    { 0 }
};

static struct argp_option options_main[] = {
    { "verbose", ARG_KEY_VERBOSE, NULL, 0, NULL, 0 },
    { "scsi", ARG_KEY_SCSI, NULL, 0, "Use SCSI security protocol command", 0 },
    { 0 }
};

struct Arguments {
    enum {
        NONE,
        CMD_UNLOCK,
        CMD_SETUP_TPER,
        CMD_SETUP_RANGE,
        CMD_SETUP_USER,
        CMD_PSID_REVERT,
        CMD_RESET,
        CMD_REGENERATE_KEY,
        CMD_LIST_RANGE,
        CMD_STACK_RESET,
        CMD_SETUP_RESET,
        CMD_ERASE_RANGE,
        CMD_SETUP_REACTIVATE,
        CMD_SETUP_ENABLE_RANGE,
        CMD_SETUP_PASSWORD,
    } command;

    char *device;
    bool use_scsi_sec;
    uint16_t locking_range;
    size_t user[32];
    size_t user_count;
    unsigned char verify_pin[PIN_MAX_LEN];
    size_t verify_pin_len;
    unsigned char assign_pin[PIN_MAX_LEN];
    size_t assign_pin_len;
    uint64_t locking_range_start;
    uint64_t locking_range_length;
    int8_t read_lock_enabled;
    int8_t write_lock_enabled;
    int8_t read_locked;
    int8_t write_locked;
    bool sum;
    bool sum_range_admin;

    size_t parsed;
} args = {
    .read_lock_enabled = VAL_UNDEFINED,
    .write_lock_enabled = VAL_UNDEFINED,
    .read_locked = VAL_UNDEFINED,
    .write_locked = VAL_UNDEFINED,
    .locking_range_start = VAL_UNDEFINED,
    .locking_range_length = VAL_UNDEFINED,
    .locking_range = ALL_LOCKING_RANGES,
};

static error_t parse_opt_pin(char *source, unsigned char *target, size_t *target_len)
{
    size_t pin_len = strlen(source);

    if (pin_len > PIN_MAX_LEN)
        return 1;

    *target_len = pin_len;
    strncpy((char *)target, source, PIN_MAX_LEN);
    return 0;
}

static error_t parse_opt_hex(const char *source, unsigned char *target, size_t *target_len)
{
    size_t i, pin_len = strlen(source);

    if (pin_len > 2 * PIN_MAX_LEN || pin_len % 2 != 0)
        return 1;

    pin_len /= 2;
    unsigned char c;

    for (i = 0; i < pin_len; i++) {
        if (sscanf(source, "%2hhx", &c) != 1)
            return 1;

        target[i] = c;
        source += 2;
    }

    *target_len = pin_len;
    return 0;
}

static error_t parse_opt_bool(const char *source, int8_t *target)
{
    if (source[0] == '0' && source[1] == 0)
        *target = 0;
    else if (source[0] == '1' && source[1] == 0)
        *target = 1;
    else
        return 1;

    return 0;
}

static error_t parse_opt_main(int key, char *arg, struct argp_state *state)
{
    struct Arguments *arguments = state->input;
    int i;

    switch (key) {
    case ARGP_KEY_INIT:
        // NOTE: 'state->root_argp->children[i].argp' does not seem to be correct.
        // FIXME: WTF?
        for (i = 0; i < 15; i++)
            state->child_inputs[i] = arguments;
        break;
    case ARG_KEY_VERBOSE:
        current_log_level = current_log_level == EVERYTHING ? EVERYTHING : current_log_level + 1;
        break;
    case ARG_KEY_SCSI:
        arguments->use_scsi_sec = true;
        break;
    case ARGP_KEY_ARG:
        switch (arguments->parsed) {
        case 0:
            if (strcmp(arg, "unlock") == 0)
                arguments->command = CMD_UNLOCK;
            else if (strcmp(arg, "setup_range") == 0)
                arguments->command = CMD_SETUP_RANGE;
            else if (strcmp(arg, "setup_user") == 0)
                arguments->command = CMD_SETUP_USER;
            else if (strcmp(arg, "setup_tper") == 0)
                arguments->command = CMD_SETUP_TPER;
            else if (strcmp(arg, "psid_revert") == 0)
                arguments->command = CMD_PSID_REVERT;
            else if (strcmp(arg, "reset") == 0)
                arguments->command = CMD_RESET;
            else if (strcmp(arg, "stack_reset") == 0)
                arguments->command = CMD_STACK_RESET;
            else if (strcmp(arg, "setup_reset") == 0)
                arguments->command = CMD_SETUP_RESET;
            else if (strcmp(arg, "regenerate_key") == 0)
                arguments->command = CMD_REGENERATE_KEY;
            else if (strcmp(arg, "erase_range") == 0)
                arguments->command = CMD_ERASE_RANGE;
            else if (strcmp(arg, "list_range") == 0)
                arguments->command = CMD_LIST_RANGE;
            else if (strcmp(arg, "setup_reactivate") == 0)
                arguments->command = CMD_SETUP_REACTIVATE;
            else if (strcmp(arg, "setup_enable_range") == 0)
                arguments->command = CMD_SETUP_ENABLE_RANGE;
            else if (strcmp(arg, "setup_password") == 0)
                arguments->command = CMD_SETUP_PASSWORD;
            else {
                printf("Unexpected command.\n");
                return ARGP_ERR_UNKNOWN;
            }
            break;
        case 1:
            arguments->device = arg;
            break;
        default:
            return ARGP_ERR_UNKNOWN;
        }
        arguments->parsed += 1;
        break;
    }
    return 0;
}

static error_t parse_opt_child(int key, char *arg, struct argp_state *state)
{
    struct Arguments *args = state->input;

    switch (key) {
    case ARG_KEY_USER:
        args->user[args->user_count] = USER_BASE_ID + strtol(arg, NULL, 10);
        args->user_count += 1;
        break;
    case ARG_KEY_ADMIN:
        args->user[args->user_count] = ADMIN_BASE_ID + strtol(arg, NULL, 10);
        args->user_count += 1;
        break;
    case ARG_KEY_LOCKING_RANGE:
        args->locking_range = strtol(arg, NULL, 10);
        break;
    case ARG_KEY_LOCKING_RANGE_START:
        args->locking_range_start = strtoull(arg, NULL, 10);
        break;
    case ARG_KEY_LOCKING_RANGE_LENGTH:
        args->locking_range_length = strtoull(arg, NULL, 10);
        break;
    case ARG_KEY_VERIFY_PIN:
        return parse_opt_pin(arg, args->verify_pin, &args->verify_pin_len);
    case ARG_KEY_VERIFY_PIN_HEX:
        return parse_opt_hex(arg, args->verify_pin, &args->verify_pin_len);
    case ARG_KEY_ASSIGN_PIN:
        return parse_opt_pin(arg, args->assign_pin, &args->assign_pin_len);
    case ARG_KEY_ASSIGN_PIN_HEX:
        return parse_opt_hex(arg, args->assign_pin, &args->assign_pin_len);
    case ARG_KEY_READ_LOCK_ENABLED:
        return parse_opt_bool(arg, &args->read_lock_enabled);
    case ARG_KEY_WRITE_LOCK_ENABLED:
        return parse_opt_bool(arg, &args->write_lock_enabled);
    case ARG_KEY_READ_LOCKED:
        return parse_opt_bool(arg, &args->read_locked);
    case ARG_KEY_WRITE_LOCKED:
        return parse_opt_bool(arg, &args->write_locked);
    case ARG_KEY_SUM:
        args->sum = true;
        break;
    case ARG_KEY_SUM_RANGE_ADMIN:
        args->sum_range_admin = true;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

int main(int argc, char **argv)
{
    struct argp argp_unlock = { options_unlock, parse_opt_child, NULL, "unlock_doc", 0, 0, 0 };
    struct argp argp_setup_range = { options_setup_range, parse_opt_child, NULL, "setup_range_doc", 0, 0, 0 };
    struct argp argp_list_range = { options_list_range, parse_opt_child, NULL, "list_range_doc", 0, 0, 0 };
    struct argp argp_setup_user = { options_setup_user, parse_opt_child, NULL, "setup_user_doc", 0, 0, 0 };
    struct argp argp_setup_tper = { options_setup_tper, parse_opt_child, NULL, "setup_tper_doc", 0, 0, 0 };
    struct argp argp_psid_revert = { options_psid_revert, parse_opt_child, NULL, "psid_revert_doc", 0, 0, 0 };
    struct argp argp_regenerate_key = { options_regenerate_key, parse_opt_child, NULL, "regenerate_key_doc", 0, 0, 0 };
    struct argp argp_erase_range = { options_erase_range, parse_opt_child, NULL, "erase_range_doc", 0, 0, 0 };
    struct argp argp_reset = { options_reset, parse_opt_child, NULL, "reset_doc", 0, 0, 0 };
    struct argp argp_stack_reset = { options_stack_reset, parse_opt_child, NULL, "stack_reset_doc", 0, 0, 0 };
    struct argp argp_setup_reset = { options_setup_reset, parse_opt_child, NULL, "setup_reset_doc", 0, 0, 0 };
    struct argp argp_setup_reactivate = { options_setup_reactivate, parse_opt_child, NULL, "setup_reactivate_doc", 0, 0, 0 };
    struct argp argp_setup_enable_range = { options_setup_enable_range, parse_opt_child, NULL, "setup_enable_range", 0, 0, 0 };
    struct argp argp_setup_password = { options_setup_password, parse_opt_child, NULL, "setup_password", 0, 0, 0 };
    struct argp_child argp_children[] = {
        { &argp_unlock, 0, "unlock - Lock or unlock a locking range", 0 },
        { &argp_setup_range, 0, "setup_range - Configure a locking range", 0 },
        { &argp_list_range, 0, "list_range - List the locking range", 0 },
        { &argp_setup_user, 0, "setup_user - Enable a user", 0 },
        { &argp_setup_tper, 0, "setup_tper - Take ownership over the device", 0 },
        { &argp_psid_revert, 0, "psid_revert - Revert the device to factory state", 0 },
        { &argp_regenerate_key, 0, "regenerate_key - Re-generate of a locking range", 0 },
        { &argp_erase_range, 0, "erase_range - Erase a locking range (single user ext.)", 0 },
        { &argp_reset, 0, "reset - Send a programmatic reset", 0 },
        { &argp_stack_reset, 0, "stack_reset - Send a stack reset", 0 },
        { &argp_setup_reset, 0, "setup_reset - Setup programmatic reset", 0 },
        { &argp_setup_reactivate, 0, "setup_reactivate - Reactivate locking ranges from/to SUM mode", 0 },
        { &argp_setup_enable_range, 0, "setup_enable_range - Setup locking for locking range", 0 },
        { &argp_setup_password, 0, "setup_password - Setup password", 0 },
        { .argp = NULL }
    };
    struct argp argp_main = { options_main, parse_opt_main, "command device", MAIN_DOC_STRING, NULL, 0, 0 };
    argp_main.children = argp_children;
    error_t err;
    struct disk_device dev = { 0 };

    err = argp_parse(&argp_main, argc, argv, 0, 0, &args);
    if (err != 0) {
        printf("Could not parse the arguments.\n");
        return 1;
    }

    if (args.parsed < 2) {
        printf("Command and disk need to be specified.\n\n");
        argp_help(&argp_main, stdout, ARGP_HELP_SHORT_USAGE|ARGP_HELP_LONG, argv[0]);
        return 1;
    }

    if ((err = disk_device_open(&dev, args.device, args.use_scsi_sec)))
        return err;

    if (args.command == CMD_UNLOCK)
        err = unlock_range(&dev, args.locking_range,
                           args.read_locked, args.write_locked,
                           args.verify_pin, args.verify_pin_len, args.user[0]);
    else if (args.command == CMD_SETUP_RANGE)
        err = setup_range(&dev, args.locking_range,
                          args.verify_pin, args.verify_pin_len, 
                          args.locking_range_start, args.locking_range_length, 
                          args.user, args.user_count, args.sum);
    else if (args.command == CMD_SETUP_USER)
        err = setup_user(&dev, args.user[0],
                         args.verify_pin, args.verify_pin_len,
                         args.assign_pin, args.assign_pin_len,
                         args.sum, args.locking_range);
    else if (args.command == CMD_SETUP_PASSWORD)
        err = setup_password(&dev, args.user, args.user_count,
                         args.verify_pin, args.verify_pin_len,
                         args.assign_pin, args.assign_pin_len);
    else if (args.command == CMD_SETUP_TPER)
        err = setup_tper(&dev, args.assign_pin, args.assign_pin_len,
                         args.sum, args.locking_range, args.sum_range_admin);
    else if (args.command == CMD_PSID_REVERT)
        err = psid_revert(&dev, args.verify_pin, args.verify_pin_len);
    else if (args.command == CMD_RESET)
        err = tper_reset(&dev);
    else if (args.command == CMD_STACK_RESET)
        err = stack_reset(&dev);
    else if (args.command == CMD_SETUP_RESET)
       err = setup_programmatic_reset(&dev, args.locking_range, args.verify_pin,
                                      args.verify_pin_len, ADMIN_BASE_ID + 1);
    else if (args.command == CMD_REGENERATE_KEY)
        err = regenerate_range(&dev, args.locking_range,
                               args.verify_pin, args.verify_pin_len, args.user[0]);
    else if (args.command == CMD_ERASE_RANGE)
        err = erase_range(&dev, args.locking_range,
                          args.verify_pin, args.verify_pin_len, ADMIN_BASE_ID + 1);
    else if (args.command == CMD_LIST_RANGE)
        err = list_range(&dev, args.locking_range,
                         args.verify_pin, args.verify_pin_len, args.user[0]);
    else if (args.command == CMD_SETUP_REACTIVATE)
        err = setup_reactivate(&dev, args.locking_range,
                               args.sum, args.sum_range_admin,
                               args.verify_pin, args.verify_pin_len);
    else if (args.command == CMD_SETUP_ENABLE_RANGE)
        err = setup_enable_range(&dev, args.locking_range,
                           args.read_lock_enabled, args.write_lock_enabled,
                           args.verify_pin, args.verify_pin_len, args.user[0]);
    else {
        printf("Invalid command.\n");
        err = 1;
    }

    disk_device_close(&dev);

    return err;
}
