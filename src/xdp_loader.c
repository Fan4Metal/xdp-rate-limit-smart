// SPDX-License-Identifier: GPL-2.0
// Minimal libbpf loader for xdp_rate_limit.bpf.o.

#include <errno.h>
#include <fcntl.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

// The BPF program's function name, as it appears in bpf_prog_info.name (kernel
// truncates to BPF_OBJ_NAME_LEN-1). Used to recognize *our own* attached program
// so we can safely replace/remove it without touching foreign XDP programs.
#define XDP_PROG_NAME "xdp_rate_limiter"

static int mkdir_p(const char *path)
{
    char tmp[PATH_MAX];
    size_t len;

    if (!path || !*path)
        return -EINVAL;

    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    if (len == 0)
        return -EINVAL;
    if (tmp[len - 1] == '/')
        tmp[len - 1] = 0;

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            if (mkdir(tmp, 0755) && errno != EEXIST)
                return -errno;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) && errno != EEXIST)
        return -errno;
    return 0;
}

static int rm_rf(const char *path)
{
    DIR *d = opendir(path);
    if (!d) {
        if (errno == ENOENT)
            return 0;
        return -errno;
    }

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
            continue;
        char child[PATH_MAX];
        snprintf(child, sizeof(child), "%s/%s", path, de->d_name);
        struct stat st;
        if (lstat(child, &st) == 0 && S_ISDIR(st.st_mode))
            rm_rf(child);
        else
            unlink(child);
    }
    closedir(d);
    rmdir(path);
    return 0;
}

static int write_text(const char *path, const char *text)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return -errno;
    ssize_t n = write(fd, text, strlen(text));
    int err = errno;
    close(fd);
    if (n < 0)
        return -err;
    return 0;
}

static int read_text(const char *path, char *buf, size_t buflen)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -errno;
    ssize_t n = read(fd, buf, buflen - 1);
    int err = errno;
    close(fd);
    if (n < 0)
        return -err;
    buf[n] = 0;
    char *nl = strchr(buf, '\n');
    if (nl)
        *nl = 0;
    return 0;
}

static int mode_flag_from_name(const char *mode)
{
    if (!strcmp(mode, "native"))
        return XDP_FLAGS_DRV_MODE;
    if (!strcmp(mode, "generic"))
        return XDP_FLAGS_SKB_MODE;
    return 0;
}

static const char *mode_name_from_flag(int flag)
{
    if (flag == XDP_FLAGS_DRV_MODE)
        return "native";
    if (flag == XDP_FLAGS_SKB_MODE)
        return "generic";
    return "unknown";
}

static int get_prog_id_from_fd(int fd, __u32 *id)
{
    struct bpf_prog_info info = {};
    __u32 len = sizeof(info);
    int ret = bpf_obj_get_info_by_fd(fd, &info, &len);
    if (ret)
        return -errno;
    *id = info.id;
    return 0;
}

// Is the program with this id one of ours? Matched by name so we never disturb
// a foreign XDP program that happens to be attached.
static bool prog_id_is_ours(__u32 id)
{
    int fd = bpf_prog_get_fd_by_id(id);
    if (fd < 0)
        return false;
    struct bpf_prog_info info = {};
    __u32 len = sizeof(info);
    int ret = bpf_obj_get_info_by_fd(fd, &info, &len);
    close(fd);
    if (ret)
        return false;
    // Kernel stores at most BPF_OBJ_NAME_LEN-1 chars; compare that many.
    return strncmp(info.name, XDP_PROG_NAME, BPF_OBJ_NAME_LEN - 1) == 0;
}

// Detach any XDP program currently attached to ifindex (native or generic) that
// is ours. With force=true, detach whatever is attached regardless of name.
// Returns the number of programs detached.
static int detach_attached(int ifindex, bool force)
{
    int modes[] = { XDP_FLAGS_DRV_MODE, XDP_FLAGS_SKB_MODE };
    int detached = 0;
    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
        __u32 id = 0;
        if (bpf_xdp_query_id(ifindex, modes[i], &id) != 0 || id == 0)
            continue;
        if (!force && !prog_id_is_ours(id)) {
            fprintf(stderr,
                    "Refusing to remove foreign %s XDP program (id %u) on ifindex %d; "
                    "detach it manually or pass --force / XDP_FORCE=1.\n",
                    mode_name_from_flag(modes[i]), id, ifindex);
            continue;
        }
        int ret = bpf_xdp_detach(ifindex, modes[i], NULL);
        if (ret == 0) {
            printf("Detached %s XDP program (id %u) from ifindex %d.\n",
                   mode_name_from_flag(modes[i]), id, ifindex);
            detached++;
        } else {
            fprintf(stderr, "Failed to detach %s XDP (id %u): %s\n",
                    mode_name_from_flag(modes[i]), id, strerror(-ret));
        }
    }
    return detached;
}

static int detach_if_ours(int ifindex, const char *pin_dir, bool force)
{
    char prog_path[PATH_MAX];
    snprintf(prog_path, sizeof(prog_path), "%s/xdp_rate_limiter", pin_dir);

    int prog_fd = bpf_obj_get(prog_path);
    if (prog_fd < 0) {
        // Pin is gone (e.g. crash or an earlier partial cleanup). Fall back to
        // name-based detach so an orphaned instance of our own program still
        // gets removed instead of wedging the interface.
        fprintf(stderr, "No pinned program at %s; falling back to name-based detach.\n", prog_path);
        detach_attached(ifindex, force);
        rm_rf(pin_dir);
        return 0;
    }

    __u32 our_id = 0;
    if (get_prog_id_from_fd(prog_fd, &our_id) < 0) {
        close(prog_fd);
        fprintf(stderr, "Unable to read pinned program id; not detaching.\n");
        return -1;
    }
    close(prog_fd);

    int modes[] = { XDP_FLAGS_DRV_MODE, XDP_FLAGS_SKB_MODE };
    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
        __u32 attached_id = 0;
        int q = bpf_xdp_query_id(ifindex, modes[i], &attached_id);
        if (q == 0 && attached_id == our_id) {
            int ret = bpf_xdp_detach(ifindex, modes[i], NULL);
            if (ret) {
                fprintf(stderr, "Failed to detach %s XDP: %s\n", mode_name_from_flag(modes[i]), strerror(-ret));
                return ret;
            }
            printf("Detached %s XDP program from ifindex %d.\n", mode_name_from_flag(modes[i]), ifindex);
        }
    }

    rm_rf(pin_dir);
    return 0;
}

static int load_prog(const char *iface, const char *obj_path, const char *pin_dir, const char *mode)
{
    int ret;
    int ifindex = if_nametoindex(iface);
    if (!ifindex) {
        fprintf(stderr, "Unknown interface: %s\n", iface);
        return 1;
    }

    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &rlim);

    ret = mkdir_p(pin_dir);
    if (ret < 0) {
        fprintf(stderr, "mkdir %s failed: %s\n", pin_dir, strerror(-ret));
        return 1;
    }

    struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object: %s\n", obj_path);
        return 1;
    }

    ret = bpf_object__load(obj);
    if (ret) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(-ret));
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_rate_limiter");
    if (!prog) {
        fprintf(stderr, "Program xdp_rate_limiter not found in object.\n");
        bpf_object__close(obj);
        return 1;
    }

    int prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get program fd.\n");
        bpf_object__close(obj);
        return 1;
    }

    // Make load idempotent: if our own program is already attached (e.g. after
    // an unclean stop that left it behind), remove it first so the fresh attach
    // below succeeds instead of failing with EBUSY. Foreign programs are left
    // alone unless XDP_FORCE=1 is set.
    bool force = getenv("XDP_FORCE") != NULL;
    detach_attached(ifindex, force);

    int attach_flags_to_try[2];
    int attach_count = 0;
    if (!strcmp(mode, "auto")) {
        attach_flags_to_try[attach_count++] = XDP_FLAGS_DRV_MODE;
        attach_flags_to_try[attach_count++] = XDP_FLAGS_SKB_MODE;
    } else {
        int flag = mode_flag_from_name(mode);
        if (!flag) {
            fprintf(stderr, "Mode must be auto, native, or generic.\n");
            bpf_object__close(obj);
            return 1;
        }
        attach_flags_to_try[attach_count++] = flag;
    }

    int attached_flag = 0;
    for (int i = 0; i < attach_count; i++) {
        int flags = attach_flags_to_try[i] | XDP_FLAGS_UPDATE_IF_NOEXIST;
        ret = bpf_xdp_attach(ifindex, prog_fd, flags, NULL);
        if (ret == 0) {
            attached_flag = attach_flags_to_try[i];
            break;
        }
        fprintf(stderr, "Attach %s failed: %s\n", mode_name_from_flag(attach_flags_to_try[i]), strerror(-ret));
    }

    if (!attached_flag) {
        fprintf(stderr, "Unable to attach XDP program. Existing XDP program may already be attached.\n");
        bpf_object__close(obj);
        rm_rf(pin_dir);
        return 1;
    }

    ret = bpf_object__pin_maps(obj, pin_dir);
    if (ret) {
        fprintf(stderr, "Failed to pin maps to %s: %s\n", pin_dir, strerror(-ret));
        bpf_xdp_detach(ifindex, attached_flag, NULL);
        bpf_object__close(obj);
        rm_rf(pin_dir);
        return 1;
    }

    char prog_pin[PATH_MAX];
    snprintf(prog_pin, sizeof(prog_pin), "%s/xdp_rate_limiter", pin_dir);
    unlink(prog_pin);
    ret = bpf_program__pin(prog, prog_pin);
    if (ret) {
        fprintf(stderr, "Failed to pin program to %s: %s\n", prog_pin, strerror(-ret));
        bpf_xdp_detach(ifindex, attached_flag, NULL);
        bpf_object__close(obj);
        rm_rf(pin_dir);
        return 1;
    }

    char mode_path[PATH_MAX];
    snprintf(mode_path, sizeof(mode_path), "%s/mode", pin_dir);
    write_text(mode_path, mode_name_from_flag(attached_flag));

    printf("Loaded and attached %s XDP program on %s. Pins: %s\n", mode_name_from_flag(attached_flag), iface, pin_dir);
    bpf_object__close(obj);
    return 0;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s load IFACE OBJ_PATH PIN_DIR [auto|native|generic]\n"
            "  %s unload IFACE PIN_DIR [--force]\n"
            "\n"
            "  XDP_FORCE=1 in the environment forces removal of a foreign XDP\n"
            "  program during load/unload (default: only our own is touched).\n",
            argv0, argv0);
}

int main(int argc, char **argv)
{
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (!strcmp(argv[1], "load")) {
        if (argc < 5 || argc > 6) {
            usage(argv[0]);
            return 1;
        }
        const char *mode = argc == 6 ? argv[5] : "auto";
        return load_prog(argv[2], argv[3], argv[4], mode);
    }

    if (!strcmp(argv[1], "unload")) {
        if (argc < 4 || argc > 5) {
            usage(argv[0]);
            return 1;
        }
        bool force = getenv("XDP_FORCE") != NULL;
        if (argc == 5) {
            if (strcmp(argv[4], "--force")) {
                usage(argv[0]);
                return 1;
            }
            force = true;
        }
        int ifindex = if_nametoindex(argv[2]);
        if (!ifindex) {
            fprintf(stderr, "Unknown interface: %s\n", argv[2]);
            return 1;
        }
        return detach_if_ours(ifindex, argv[3], force);
    }

    usage(argv[0]);
    return 1;
}
