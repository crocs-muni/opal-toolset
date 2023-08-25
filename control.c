// SPDX-License-Identifier: MIT

#include <argp.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "utils.h"
#include "common.h"

#define MAIN_DOC_STRING                                                                                                \
    "        device               File of Opal-compliant disk\n"                                                       \
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
    ARG_KEY_SCSI = 'S'
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
    { "locking-range", ARG_KEY_LOCKING_RANGE, "id", 0, "Locking range to list", 0 },
    { 0 }
};

static struct argp_option options_setup_user[] = {
    { "verify-pin", ARG_KEY_VERIFY_PIN, "pin", 0, "Password of Admin1 authority", 0 },
    { "verify-pin-hex", ARG_KEY_VERIFY_PIN_HEX, "hex_pin", 0, "Password of Admin1 authority", 0 },
    { "assign-pin", ARG_KEY_ASSIGN_PIN, "pin", 0, "Password to assign to selected user authority", 0 },
    { "assign-pin-hex", ARG_KEY_ASSIGN_PIN_HEX, "hex_pin", 0, "Password to assign to selected user authority", 0 },
    { "user", ARG_KEY_USER, "id", 0, "ID of the user authority", 0 },
    { 0 }
};

static struct argp_option options_setup_tper[] = { 
    { "assign-pin", ARG_KEY_ASSIGN_PIN, "pin", 0, "Password to assign to the owner authority", 0 },
    { "assign-pin-hex", ARG_KEY_ASSIGN_PIN_HEX, "hex_pin", 0, "Password to assign to the owner authority", 0 },
    { 0 }
};

static struct argp_option options_psid_revert[] = { 
    { "verify-pin", ARG_KEY_VERIFY_PIN, "pin", 0, "PSID", 0 },
    { "verify-pin-hex", ARG_KEY_VERIFY_PIN_HEX, "hex_pin", 0, "PSID", 0 },
    { 0 } 
};

static struct argp_option options_regenerate_key[] = {
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

static struct argp_option options_reset[] = { 
    { "No options", 0, "NULL", OPTION_DOC},
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

    size_t parsed;
} args = {
    .read_lock_enabled = VAL_UNDEFINED,
    .write_lock_enabled = VAL_UNDEFINED,
    .read_locked = VAL_UNDEFINED,
    .write_locked = VAL_UNDEFINED,
    .locking_range_start = VAL_UNDEFINED,
    .locking_range_length = VAL_UNDEFINED,
};

static error_t parse_opt_pin(char *source, unsigned char *target, size_t *target_len)
{
    size_t pin_len = strlen(source);

    if (pin_len > PIN_MAX_LEN) {
        return 1;
    }

    *target_len = pin_len;
    strncpy((char *)target, source, PIN_MAX_LEN);
    return 0;
}

static error_t parse_opt_hex(const char *source, unsigned char *target, size_t *target_len)
{
    size_t pin_len = strlen(source);

    if (pin_len > 2 * PIN_MAX_LEN || pin_len % 2 != 0) {
        return 1;
    }

    pin_len /= 2;
    unsigned char c;

    for (int i = 0; i < pin_len; i++) {
        if (sscanf(source, "%2hhx", &c) != 1) {
            return 1;
        }

        target[i] = c;
        source += 2;
    }

    *target_len = pin_len;
    return 0;
}

static error_t parse_opt_bool(const char *source, int8_t *target)
{
    if (source[0] == '0' && source[1] == 0) {
        *target = 0;
    } else if (source[0] == '1' && source[1] == 0) {
        *target = 1;
    } else {
        return 1;
    }

    return 0;
}

static error_t parse_opt_main(int key, char *arg, struct argp_state *state)
{
    struct Arguments *arguments = state->input;

    switch (key) {
    case ARGP_KEY_INIT:
        // NOTE: 'state->root_argp->children[i].argp' does not seem to be correct.
        for (int i = 0; i < 8; i++) {
            state->child_inputs[i] = arguments;
        }
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
            if (strcmp(arg, "unlock") == 0) {
                arguments->command = CMD_UNLOCK;
            } else if (strcmp(arg, "setup_range") == 0) {
                arguments->command = CMD_SETUP_RANGE;
            } else if (strcmp(arg, "setup_user") == 0) {
                arguments->command = CMD_SETUP_USER;
            } else if (strcmp(arg, "setup_tper") == 0) {
                arguments->command = CMD_SETUP_TPER;
            } else if (strcmp(arg, "psid_revert") == 0) {
                arguments->command = CMD_PSID_REVERT;
            } else if (strcmp(arg, "reset") == 0) {
                arguments->command = CMD_RESET;
            } else if (strcmp(arg, "regenerate_key") == 0) {
                arguments->command = CMD_REGENERATE_KEY;
            } else if (strcmp(arg, "list_range") == 0) {
                arguments->command = CMD_LIST_RANGE;
            } else {
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
    struct argp argp_reset = { options_reset, parse_opt_child, NULL, "reset_doc", 0, 0, 0 };
    struct argp_child argp_children[] = {
        { &argp_unlock, 0, "unlock - Lock or unlock a locking range", 0 },
        { &argp_setup_range, 0, "setup_range - Configure a locking range", 0 },
        { &argp_list_range, 0, "list_range - List the locking range", 0 },
        { &argp_setup_user, 0, "setup_user - Enable a user", 0 },
        { &argp_setup_tper, 0, "setup_tper - Take ownership over the device", 0 },
        { &argp_psid_revert, 0, "psid_revert - Revert the device to factory state", 0 },
        { &argp_regenerate_key, 0, "regenerate_key - Re-generate of a locking range", 0 },
        { &argp_reset, 0, "reset - Send a programmatic reset", 0 },
        { .argp = NULL }
    };
    struct argp argp_main = { options_main, parse_opt_main, "device command", MAIN_DOC_STRING, NULL, 0, 0 };
    argp_main.children = argp_children;

    error_t err = argp_parse(&argp_main, argc, argv, 0, 0, &args);
    if (err != 0) {
        printf("Could not parse the arguments.\n");
        return 1;
    }

    if (args.parsed < 2) {
        printf("Command and disk need to be specified.\n");
        argp_help(&argp_main, stdout, ARGP_HELP_SEE, argv[0]);
        return 1;
    }

    struct disk_device dev = { 0 };
    if ((err = disk_device_open(&dev, args.device, args.use_scsi_sec))) {
        return err;
    }

    if (args.command == CMD_UNLOCK) {
        err = unlock_range(&dev, args.locking_range, args.user[0], 
                           args.read_locked, args.write_locked, 
                           args.verify_pin, args.verify_pin_len);
    } else if (args.command == CMD_SETUP_RANGE) {
        err = setup_range(&dev, args.locking_range, 
                          args.verify_pin, args.verify_pin_len, 
                          args.locking_range_start, args.locking_range_length, 
                          args.user, args.user_count);
    } else if (args.command == CMD_SETUP_USER) {
        err = setup_user(&dev, args.user[0], 
                         args.verify_pin, args.verify_pin_len,
                         args.assign_pin, args.assign_pin_len);
    } else if (args.command == CMD_SETUP_TPER) {
        err = setup_tper(&dev, args.assign_pin, args.assign_pin_len);
        if (!err)
            err = setup_programmatic_reset(&dev, args.assign_pin, args.assign_pin_len, -1);
    } else if (args.command == CMD_PSID_REVERT) {
        err = psid_revert(&dev, args.verify_pin, args.verify_pin_len);
    } else if (args.command == CMD_RESET) {
        err = tper_reset(&dev);
    } else if (args.command == CMD_REGENERATE_KEY) {
        err = regenerate_key(&dev, args.locking_range, 
                             args.verify_pin, args.verify_pin_len);
    } else if (args.command == CMD_LIST_RANGE) {
        err = list_range(&dev, args.locking_range,
                         args.verify_pin, args.verify_pin_len, args.user[0]);
    } else {
        printf("Invalid command.\n");

        err = 1;
    }

    disk_device_close(&dev);

    return err;
}
