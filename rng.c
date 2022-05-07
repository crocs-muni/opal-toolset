// SPDX-License-Identifier: MIT

#include "common.h"
#include "utils.h"

static void print_usage(char *prog_name)
{
    fprintf(stderr,
            "Usage: %s <device> [bytes [repeats [log_level]]]\n"
            "\n"
            "Bytes are acquired in chunks of 32 bytes.\n"
            "Each repeat is a separate session.\n",
            prog_name);
    exit(1);
}

int main(int argc, char **argv)
{
    int err = 0;
    const char *dev_file = NULL;
    int req_repeats = 1;
    int req_bytes = 32;

    switch (argc) {
    case 5:
        current_log_level = atoi(argv[4]);
        if (current_log_level < ERROR || current_log_level > EVERYTHING) {
            print_usage(argv[0]);
        }
        // fallthrough
    case 4:
        req_repeats = atoi(argv[3]);
        if (req_repeats <= 0) {
            print_usage(argv[0]);
        }
        // fallthrough
    case 3:
        req_bytes = atoi(argv[2]);
        if (req_bytes <= 0) {
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
    if ((err = disk_device_open(&dev, dev_file))) {
        return err;
    }

    for (int req_i = 0; req_i < req_repeats; ++req_i) {
        unsigned char buffer[req_bytes];

        if ((err = get_random(&dev, buffer, req_bytes))) {
            LOG(ERROR, "Failed to get random data.\n");
            break;
        }

        for (int byte_i = 0; byte_i < req_bytes; ++byte_i) {
            printf("%02x", buffer[byte_i]);
        };
        printf("\n");
    }

    disk_device_close(&dev);

    return err;
}
