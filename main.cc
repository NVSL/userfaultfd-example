///bin/true;COMPILER_OPTIONS="-g -Wall -Wextra -O0 -pthread";THIS_FILE="$(cd "$(dirname "$0")"; pwd -P)/$(basename "$0")";OUT_FILE="/tmp/build-cache/$THIS_FILE";mkdir -p "$(dirname "$OUT_FILE")";test "$THIS_FILE" -ot "$OUT_FILE" || $(which clang++ || which g++) $COMPILER_OPTIONS -xc++ "$THIS_FILE" -o "$OUT_FILE" || exit;exec "$OUT_FILE" "$@"
// -*- mode: c++; c-basic-offset: 2; -*-

/**
 * @file   main.cc
 * @date   mars  9, 2022
 * @brief  Brief description here
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <bitset>
#include <cassert>
#include <fcntl.h>
#include <fstream>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <iostream>

static inline std::string PSTR() {
  return std::string(__FILE__) + ":" + std::to_string(__LINE__) + " " +
         std::string(strerror(errno));
}

static int fd;

int userfaultfd(int flags) {
  return syscall(SYS_userfaultfd, flags);
}

int register_addr_range(void *start, size_t range) {
  assert(fd != 0 && "fd not initialized");

  std::cout << "userfaultd's fd = " << fd << std::endl;

  struct uffdio_register reg = {};

  // reg.mode        = UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP;
  reg.mode = UFFDIO_REGISTER_MODE_MISSING;
  reg.range = {};
  reg.range.start = (unsigned long long)start;
  reg.range.len = (unsigned long long)range;

  int res = ioctl(fd, UFFDIO_REGISTER, &reg);
  if (res != 0) {
    // std::cout << "Error code:  = " << res << std::endl;
    perror("ioctl(fd, UFFDIO_REGISTER, ...) failed");
    goto error;
  }

  if (reg.ioctls != UFFD_API_RANGE_IOCTLS) {
    std::cout << "UFFD_API_RANGE_IOCTLS:  = "
            << std::bitset<64>(UFFD_API_RANGE_IOCTLS) << std::endl;
    std::cout << "reg.ioctls           :  = " << std::bitset<64>(reg.ioctls)
            << std::endl;
  }

  return 0;

error:
  return -1;
}

void *handle_page_faults(void *args) {
  struct pollfd evt = {};
  evt.fd = fd;
  evt.events = POLLIN;

  while (1) {
    int pollval = poll(&evt, 1, 10);

    switch (pollval) {
    case -1:
      perror("poll/userfaultfd");
      continue;
    case 0:
      continue;
    case 1:
      std::cout << "Handling page fault!" << std::endl;
      break;
    default:
      std::cerr << "unexpected poll result" << std::endl;
      exit(1);
    }

    /* unexpected poll events */
    if (evt.revents & POLLERR) {
      std::cerr << "++ POLLERR" << std::endl;
      goto error;
    } else if (evt.revents & POLLHUP) {
      std::cerr << "++ POLLHUP" << std::endl;
      goto error;
    }
    struct uffd_msg fault_msg = {0};
    if (read(fd, &fault_msg, sizeof(fault_msg)) != sizeof(fault_msg)) {
      perror("ioctl_userfaultfd read");
      std::cerr << "++ read failed" << std::endl;
      goto error;
    }
    char *place = (char *)fault_msg.arg.pagefault.address;
    std::cout << "Got page fault at " << (void*)(place) << std::endl;

    /* handle the page fault by copying a page worth of bytes */
    if (fault_msg.event & UFFD_EVENT_PAGEFAULT) {
      struct uffdio_range range = {};
      auto page_aligned = ((uint64_t)place/4096)*4096;
      range.start = page_aligned;
      range.len = 4096;

      mmap((void*)range.start, range.len,
           PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
           -1, 0);
      // *(uint64_t*)range.start = 0x0;

      if (ioctl(fd, UFFDIO_WAKE, &range) == -1) {
        perror("ioctl/wake");
        exit(1);
      } else {
        std::cerr << "fault handled\n";
      }
    }
  }

error:
  if (fd) close(fd);
  std::cerr << "Cannot continue, exiting with code 1..." << std::endl;
  exit(1);
}

int register_handlers_internal() {
  std::cout << "Registering handlers" << std::endl;

  auto error = []() { return -1; };

  /* Open a userfaultd filedescriptor */
  if ((fd = userfaultfd(O_NONBLOCK)) == -1) {
    std::cerr << PSTR() + ": ++ userfaultfd failed" << std::endl;
    return error();
  }

  /* Check if the kernel supports the read/POLLIN protocol */
  struct uffdio_api uapi = {};
  uapi.api = UFFD_API;
  if (ioctl(fd, UFFDIO_API, &uapi)) {
    std::cerr << PSTR() + ": ++ ioctl(fd, UFFDIO_API, ...) failed" << std::endl;
    return error();
  }

  if (uapi.api != UFFD_API) {
    std::cerr << PSTR() + ": ++ unexepcted UFFD api version." << std::endl;
    return error();
  }

  /* Start a fault monitoring thread */
  /* start a thread that will fault... */
  pthread_t thread = {0};
  if (pthread_create(&thread, NULL, handle_page_faults, NULL)) {
    std::cerr << PSTR() + ": ++ pthread_create failed" << std::endl;
    return error();
  }

  return 0;
}

int register_handlers() {
  return register_handlers_internal();
}

void sigsegv_handler(int sig) {
  if (sig == SIGSEGV || sig == SIGABRT) {
    std::cerr << "*** FATAL libpuddles *** Signal " << sig
              << " caught, printing stack trace..." << std::endl;
  }
  exit(1);
}

void register_crash_handlers() { signal(SIGSEGV, sigsegv_handler); }

int main() {
  if (register_handlers()) {
    std::cerr << "Error registering handler" << std::endl;
    exit(1);
  }

  constexpr size_t page_cnt = 10;
  constexpr size_t page_sz = 4096;
  constexpr size_t arr_sz = page_cnt*page_sz;
  uint8_t *arr = (uint8_t*)mmap(nullptr, arr_sz, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

  if (arr == (uint8_t*)-1) {
    std::cerr << "mmap failed: " << PSTR() << std::endl;
    exit(1);
  }
  
  register_addr_range(arr, arr_sz);

  size_t i = 0;
  while (i < page_cnt) {
    std::cout << "Writing to page " << i << std::endl;
    arr[i*page_sz]++;
    std::cout << "Written to page " << i << std::endl;
    sleep(1);
    i++;
  }
}
