// SPDX-License-Identifier: MIT

#include "common.h"
#include "utils.h"

#include <errno.h>

#define BUFFER_SIZE 512

enum arg_keys
{
    ARG_KEY_DEVICE_FILE = 'd',
    ARG_KEY_REQ_BYTES = 'b',
    ARG_KEY_REQ_REPEATS = 'r',
    ARG_KEY_OUTPUT_FILE = 'o',
    ARG_KEY_LOG_LEVEL = 'l',
    ARG_KEY_USE_SCSI = 's',
    ARG_KEY_HEX_OUTPUT = 'x',
};

static struct argp_option options[] = {
    { "device", ARG_KEY_DEVICE_FILE, "device", 0, "Disk device", 0 },
    { "bytes", ARG_KEY_REQ_BYTES, "number of bytes", 0, "Number of random bytes within a sequence", 0 },
    { "repeats", ARG_KEY_REQ_REPEATS, "number of repeats", 0, "Number of random byte sequences to acquire", 0 },
    { "output", ARG_KEY_OUTPUT_FILE, "file", 0, "Output file", 0 },
    { "log-level", ARG_KEY_LOG_LEVEL, "level", 0, "Log level", 0 },
    { "scsi", ARG_KEY_USE_SCSI, 0, 0, "Use SCSI", 0 },
    { "hex", ARG_KEY_HEX_OUTPUT, 0, 0, "Output random bytes in hexadecimal", 0 },
    { 0 }
};

struct arguments
{
    char *dev_file;
    char *out_file_name;
    size_t req_bytes;
    size_t req_repeats;
    bool use_scsi_sec;
    bool hex_output;
} args = {
    .dev_file = NULL,
    .out_file_name = NULL,
    .req_bytes = 32,
    .req_repeats = 1,
    .use_scsi_sec = false,
    .hex_output = false,
};

static size_t min(size_t a, size_t b)
{
    return a < b ? a : b;
}

// TODO update or replace with arpg_usage function
static void print_usage(char *prog_name)
{
    fprintf(stderr,
            "Usage: %s <device> [bytes [repeats [log_level]]] [--scsi]\n"
            "\n"
            "Bytes are acquired in chunks of 32 bytes.\n"
            "Each repeat is a separate session.\n",
            prog_name);
    exit(1);
}

// TODO indicate cause of error
static error_t parse_num(char *num_str, size_t *num_out)
{
    char *end;
    long tmp;
    errno = 0;

    tmp = strtol(num_str, &end, 10);

    if (errno != 0 || num_str == end || *end != '\0' || tmp <= 0) {
        return 1;
    }

    *num_out = tmp;
    return 0;
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arguments *args = state->input;

    switch (key) {
    case ARG_KEY_DEVICE_FILE:
        args->dev_file = arg;
        break;
    case ARG_KEY_REQ_BYTES:
        if (parse_num(arg, &args->req_bytes)) {
            return 1;
        }
        break;
    case ARG_KEY_REQ_REPEATS:
        if (parse_num(arg, &args->req_repeats)) {
            return 1;
        }
        break;
    case ARG_KEY_OUTPUT_FILE:
        args->out_file_name = arg;
        break;
    case ARG_KEY_LOG_LEVEL:
        size_t tmp;
        if (parse_num(arg, &tmp) || tmp < ERROR || tmp > EVERYTHING) {
            return 1;
        }
        current_log_level = tmp;
        break;
    case ARG_KEY_USE_SCSI:
        args->use_scsi_sec = true;
    case ARG_KEY_HEX_OUTPUT:
        args->hex_output = true;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static struct argp argp = { options, parse_opt, 0, 0 };

int main(int argc, char **argv)
{
    int err = 0;
    unsigned char *buffer = NULL;

    if (argp_parse(&argp, argc, argv, 0, 0, &args) || args.dev_file == NULL) {
        print_usage("rng");
        err = 1;
        goto exit;
    }

    if (!(buffer = malloc(BUFFER_SIZE))) {
        LOG(ERROR, "Out of memory.\n");
        err = 1;
        goto exit;
    }

    struct disk_device dev = { 0 };
    if ((err = disk_device_open(&dev, args.dev_file, args.use_scsi_sec))) {
        LOG(ERROR, "Failed to open device file.\n");
        err = 1;
        goto buffer_cleanup;
    }

    FILE *out = stdout;
    if (args.out_file_name != NULL && (out = fopen(args.out_file_name, "a")) == NULL) {
        LOG(ERROR, "Failed to open output file.\n");
        err = 1;
        goto disk_cleanup;
    }

    for (int req_i = 0; req_i < args.req_repeats; ++req_i) {
        size_t bytes_read = 0;

        while (bytes_read < args.req_bytes) {
            memset(buffer, 0, BUFFER_SIZE);
            size_t current_req_bytes = min(args.req_bytes - bytes_read, BUFFER_SIZE);

            if ((err = get_random(&dev, buffer, current_req_bytes))) {
                LOG(ERROR, "Failed to get random data.\n");
                err = 1;
                break;
            }

            // TODO allow hexadecimal output
            if (fwrite(buffer, sizeof(char), current_req_bytes, out) != current_req_bytes) {
                LOG(ERROR, "Failed to write random data.\n");
                err = 1;
                break;
            }

            bytes_read += current_req_bytes;
        }
    }

    fclose(out);
disk_cleanup:
    disk_device_close(&dev);
buffer_cleanup:
    free(buffer);
exit:
    return err;
}
