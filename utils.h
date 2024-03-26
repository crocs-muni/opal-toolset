// SPDX-License-Identifier: MIT

#ifndef UTILS_H_
#define UTILS_H_

#include <stddef.h>
#include <stdint.h>

struct disk_device;

int unlock_range(struct disk_device *dev, unsigned char locking_range, size_t user_uid, 
                 char read_locked, char write_locked, 
                 unsigned char *challenge, size_t challenge_len);

int setup_range(struct disk_device *dev, unsigned char locking_range,
                unsigned char *challenge, size_t challenge_len, 
                uint64_t start, uint64_t length, size_t users[], size_t users_len);

int list_range(struct disk_device *dev, unsigned locking_range, unsigned char *challenge, size_t challenge_len, size_t user);

int setup_user(struct disk_device *dev, size_t user_uid,
               unsigned char *admin_pin, size_t admin_pin_len,
               unsigned char *user_pin, size_t user_pin_len);

int setup_programmatic_reset(struct disk_device *dev, const unsigned char *pwd, size_t pwd_len, 
                             char locking_range);

int tper_reset(struct disk_device *dev);

int setup_tper(struct disk_device *dev, const unsigned char *sid_pwd, size_t sid_pwd_len);

int psid_revert(struct disk_device *dev, const unsigned char *psid, size_t psid_len);

int get_random(struct disk_device *dev, unsigned char *output, size_t output_len);

int get_random_session(struct disk_device *dev, unsigned char *output, size_t output_len);

int regenerate_key(struct disk_device *dev, unsigned char locking_range,
                   unsigned char *admin_pin, size_t admin_pin_len);

#endif // UTILS_H_
