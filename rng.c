// SPDX-License-Identifier: MIT

#include "common.h"
#include "utils.h"

#include <errno.h>

#define MAIN_DOC_STRING "\n        DEVICE               File of Opal-compliant disk\n"

enum arg_keys
{
    ARG_KEY_REQ_BYTES = 'b',
    ARG_KEY_CHUNK_SIZE = 'c',
    ARG_KEY_OUTPUT_FILE = 'o',
    ARG_KEY_LOG_LEVEL = 'l',
    ARG_KEY_USE_SCSI = 's',
    ARG_KEY_HEX_OUTPUT = 'x',
};

static struct argp_option options[] = {
    { "bytes", ARG_KEY_REQ_BYTES, "number of bytes", 0, "Number of random bytes within a sequence (defaults to 32 bytes)", 0 },
    { "chunk-size", ARG_KEY_CHUNK_SIZE, "size of chunks in bytes", 0, "Divide acquisition of the random sequence into chunks of a specified size (defaults to 512 bytes)", 0 },
    { "output", ARG_KEY_OUTPUT_FILE, "file", 0, "Output file for binary output, use \"-\" for binary stdout output (defaults to stdout hexadecimal output)", 0 },
    { "log-level", ARG_KEY_LOG_LEVEL, "level", 0, "Log level", 0 },
    { "scsi", ARG_KEY_USE_SCSI, 0, 0, "Use SCSI", 0 },
    { "hex", ARG_KEY_HEX_OUTPUT, 0, 0, "Output random bytes in hexadecimal, only available for stdout output", 0 },
    { 0 }
};

struct arguments
{
    char *dev_file;
    char *out_file_name;
    size_t req_bytes;
    size_t chunk_size;
    bool use_scsi_sec;
    bool hex_output;
} args = {
    .dev_file = NULL,
    .out_file_name = NULL,
    .req_bytes = 32,
    .chunk_size = 512,
    .use_scsi_sec = false,
    .hex_output = false,
};

static size_t min(size_t a, size_t b)
{
    return a < b ? a : b;
}

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
    size_t tmp;

    switch (key) {
    case ARG_KEY_REQ_BYTES:
        if (parse_num(arg, &args->req_bytes)) {
            argp_err_exit_status = 1;
            argp_error(state, "Invalid numeric argument for -%c option provided.", ARG_KEY_REQ_BYTES);
        }
        break;
    case ARG_KEY_CHUNK_SIZE:
        if (parse_num(arg, &args->chunk_size)) {
            argp_err_exit_status = 1;
            argp_error(state, "Invalid numeric argument for -%c option provided.", ARG_KEY_CHUNK_SIZE);
        }
        break;
    case ARG_KEY_OUTPUT_FILE:
        args->out_file_name = arg;
        break;
    case ARG_KEY_LOG_LEVEL:
        if (parse_num(arg, &tmp) || tmp > EVERYTHING) {
            argp_err_exit_status = 1;
            argp_error(state, "Invalid numeric argument for -%c option provided.", ARG_KEY_LOG_LEVEL);
        }
        current_log_level = tmp;
        break;
    case ARG_KEY_USE_SCSI:
        args->use_scsi_sec = true;
        break;
    case ARG_KEY_HEX_OUTPUT:
        args->hex_output = true;
        break;
    case ARGP_KEY_ARG:
        if (state->arg_num >= 1) {
            argp_err_exit_status = 1;
            argp_error(state, "Too many arguments given.");
        }
        args->dev_file = arg;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static struct argp argp = { options, parse_opt, "DEVICE", MAIN_DOC_STRING };

static size_t write_buffer(int fd, const void *buf, size_t length)
{
        size_t write_size = 0;
        ssize_t w;

        do {
            w = write(fd, buf, length - write_size);
            if (w < 0 && errno != EINTR)
                return w;
            if (w > 0) {
                write_size += (size_t) w;
                buf = (const uint8_t*)buf + w;
            }
        } while (w == 0 || write_size != length);

        return write_size;
}

int main(int argc, char **argv)
{
    struct disk_device dev = { 0 };
    int fd = -1, err = 1, fail_repeat_count = 0;
    unsigned char *buffer = NULL;
    size_t current_req_bytes, bytes_read = 0, written;

    argp_parse(&argp, argc, argv, 0, 0, &args);

    if (args.dev_file == NULL) {
        fprintf(stderr, "The disk device file must be specified.\n");
        argp_help(&argp, stdout, ARGP_HELP_SHORT_USAGE, argv[0]);
        goto fail;
    }

    if (!(buffer = malloc(args.chunk_size))) {
        LOG(ERROR, "Out of memory.\n");
        goto fail;
    }

    if ((err = disk_device_open(&dev, args.dev_file, args.use_scsi_sec))) {
        LOG(ERROR, "Failed to open device file.\n");
        goto fail;
    }

    if (!args.out_file_name)
        args.hex_output = true;

    if (args.out_file_name && args.hex_output) {
        LOG(ERROR, "Hex output is possible only to stdout.\n");
        goto fail;
    }

    if (!args.out_file_name || !strcmp(args.out_file_name, "-"))
        fd = STDOUT_FILENO;
    else
        fd = open(args.out_file_name, O_WRONLY|O_CREAT|O_APPEND, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);

    if (fd == -1) {
        LOG(ERROR, "Failed to open output file.\n");
        goto fail;
    }

    err = 0;
    while (bytes_read < args.req_bytes) {
        memset(buffer, 0, args.chunk_size);
        current_req_bytes = min(args.req_bytes - bytes_read, args.chunk_size);

        if ((err = get_random(&dev, buffer, current_req_bytes))) {
            LOG(ERROR, "Failed to get random data.\n");
            if (++fail_repeat_count < 5) {
                sleep(1);
                continue;
            }
            err = 1;
            break;
        }
        fail_repeat_count = 0;

        if (args.hex_output) {
            size_t byte_i;
            bool eol;
            for (byte_i = 0; byte_i < current_req_bytes; byte_i++) {
                eol = !((byte_i + 1) % 32);
                fprintf(stdout, "%02x%s", buffer[byte_i], eol ? "\n" : "");
            }
            if (!eol)
                fprintf(stdout, "\n");
            fflush(stdout);
            written = current_req_bytes;
        } else {
            written = write_buffer(fd, buffer, current_req_bytes);
            fdatasync(fd);
        }

        if (written != current_req_bytes) {
            LOG(ERROR, "Failed to write random data.\n");
            err = 1;
            break;
        }

        bytes_read += current_req_bytes;
    }

fail:
    if (fd != -1)
        close(fd);
    disk_device_close(&dev);
    free(buffer);
    return err;
}
