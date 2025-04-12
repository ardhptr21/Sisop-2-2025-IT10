#define _DEFAULT_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define FILE_DRIVE "https://drive.google.com/uc?export=download&id=1_5GxIGfQr3mNKuavJbte_AoRkEQLXSKS"

void daemonize(char *argv0, char *daemonName);
void spawn_process(char *argv0, char *processName, int (*callback)(char *argv0));
void help();
void download_extract_zip();
unsigned char *base64_decode(char *text, size_t *outlen);
int decrypt_filename();
int move_files(char *old_folder, char *new_folder);
int delfiles(char *foldername);
int shutdown(char *processName);
void logger(char *message);
int run_command(char *cmd, char *args[]);

static const signed char b64invs[80] = {
    62, -1, -1, -1, 63,                                    // + , - . / 0
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61,                // 1-9
    -1, -1, -1, -1, -1, -1, -1,                            // : ; < = > ? @
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,  // A-O
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25,                // P-Z
    -1, -1, -1, -1, -1, -1,                                // [ \ ] ^ _ `
    26, 27, 28, 29, 30, 31, 32, 33, 34, 35,                // a-j
    36, 37, 38, 39, 40, 41, 42, 43, 44, 45,                // k-t
    46, 47, 48, 49, 50, 51                                 // u-z
};

int main(int argc, char *argv[]) {
    download_extract_zip();
    if (argc < 2 || argc > 2) {
        help();
        return 1;
    }

    char *command = argv[1];
    if (strcmp(command, "--decrypt") == 0) {
        daemonize(argv[0], "starterkit-decryptor");
        while (1) {
            decrypt_filename();
            sleep(1);
        }
    } else if (strcmp(command, "--quarantine") == 0) {
        move_files("starter_kit", "quarantine");
    } else if (strcmp(command, "--return") == 0) {
        move_files("quarantine", "starter_kit");
    } else if (strcmp(command, "--eradicate") == 0) {
        delfiles("quarantine");
    } else if (strcmp(command, "--shutdown") == 0) {
        shutdown("starterkit-decryptor");
    } else {
        help();
        return 1;
    }

    return 0;
}

void daemonize(char *argv0, char *daemonName) {
    prctl(PR_SET_NAME, daemonName, 0, 0, 0);
    strncpy(argv0, daemonName, 512);

    pid_t pid = fork();
    int status;

    if (pid < 0) exit(1);
    if (pid > 0) exit(0);
    if (setsid() < 0) exit(1);

    umask(0);
    for (int x = sysconf(_SC_OPEN_MAX); x > 0; x--) close(x);
    char message[256];
    snprintf(message, sizeof(message), "Successfully started decryption process with PID %d", getpid());
    logger(message);
}

void spawn_process(char *argv0, char *processName, int (*callback)(char *argv0)) {
    pid_t pid = fork();
    if (pid < 0 || pid > 0) return;

    prctl(PR_SET_PDEATHSIG, SIGTERM);
    if (argv0 != NULL && processName != NULL) {
        prctl(PR_SET_NAME, processName, 0, 0, 0);
        strncpy(argv0, processName, 128);
    }
    exit(callback(argv0));
}

void help() {
    printf("Usage: starterkit <command>\n");
    printf("Available commands:\n");
    printf("\t--decrypt\n");
    printf("\t--quarantine\n");
    printf("\t--return\n");
    printf("\t--eradicate\n");
    printf("\t--shutdown\n");
}

int run_command(char *cmd, char *args[]) {
    pid_t pid = fork();
    if (pid == 0) {
        execvp(cmd, args);
        exit(EXIT_FAILURE);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        return WIFEXITED(status) && WEXITSTATUS(status) == 0;
    } else {
        return 0;
    }
}

void download_extract_zip() {
    struct stat st;
    if (stat("starter_kit", &st) == 0 && S_ISDIR(st.st_mode)) return;
    printf("Initializing program, downloading and extract zip...\n");

    char *wget_args[] = {"wget", "-q", "-O", "starter_kit.zip", "--no-check-certificate", FILE_DRIVE, NULL};
    run_command("/bin/wget", wget_args);

    char *unzip_args[] = {"unzip", "-q", "starter_kit.zip", "-d", "starter_kit", NULL};
    run_command("/bin/unzip", unzip_args);

    remove("starter_kit.zip");
}

int is_base64(char *str) {
    const char *base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    size_t len = strlen(str);
    if (len % 4 != 0) return 0;
    for (size_t i = 0; i < len; i++) {
        if (strchr(base64_chars, str[i]) == NULL) return 0;
    }
    return 1;
}

size_t b64_decoded_size(const char *text) {
    size_t len = strlen(text);
    size_t ret = len / 4 * 3;

    if (len >= 1 && text[len - 1] == '=') ret--;
    if (len >= 2 && text[len - 2] == '=') ret--;

    return ret;
}

unsigned char *base64_decode(char *text, size_t *outlen) {
    size_t len = strlen(text);
    size_t decoded_len = b64_decoded_size(text);
    unsigned char *out = malloc(decoded_len);
    if (!out) return NULL;

    int v;
    size_t i, j;
    for (i = 0, j = 0; i < len; i += 4, j += 3) {
        v = b64invs[text[i] - 43];
        v = (v << 6) | b64invs[text[i + 1] - 43];
        v = (text[i + 2] == '=') ? (v << 6) : ((v << 6) | b64invs[text[i + 2] - 43]);
        v = (text[i + 3] == '=') ? (v << 6) : ((v << 6) | b64invs[text[i + 3] - 43]);

        out[j] = (v >> 16) & 0xFF;
        if (text[i + 2] != '=') out[j + 1] = (v >> 8) & 0xFF;
        if (text[i + 3] != '=') out[j + 2] = v & 0xFF;
    }

    if (outlen) *outlen = decoded_len;
    return out;
}

void sanitize_filename(unsigned char *buf, size_t len) {
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (isprint(buf[i]) && buf[i] != '/' && buf[i] != '\\' && buf[i] != '\n' && buf[i] != '\r') {
            buf[j++] = buf[i];
        }
    }
    buf[j] = '\0';
}
int decrypt_filename() {
    char *foldername = "quarantine";
    struct stat st;
    if (stat(foldername, &st) == -1) {
        if (mkdir(foldername, 0700) == -1) return 1;
    }

    DIR *dir = opendir(foldername);
    if (dir == NULL) return 1;

    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        if (entry->d_type == DT_DIR) continue;
        if (strrchr(entry->d_name, '.')) continue;
        if (!is_base64(entry->d_name)) continue;

        size_t decoded_len;
        unsigned char *decoded_name = base64_decode(entry->d_name, &decoded_len);
        if (!decoded_name) continue;

        sanitize_filename(decoded_name, decoded_len);

        char new_name[PATH_MAX], old_name[PATH_MAX];
        snprintf(old_name, sizeof(old_name), "%s/%s", foldername, entry->d_name);
        snprintf(new_name, sizeof(new_name), "%s/%s", foldername, decoded_name);

        rename(old_name, new_name);
        free(decoded_name);
    }

    closedir(dir);
    return 0;
}

int move_files(char *old_folder, char *new_folder) {
    DIR *dir;
    struct dirent *entry;
    struct stat st;
    char old_path[PATH_MAX], new_path[PATH_MAX];

    dir = opendir(old_folder);
    if (!dir) return -1;

    if (stat(new_folder, &st) == -1) {
        if (mkdir(new_folder, 0755) == -1) {
            closedir(dir);
            return -1;
        }
    }

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        if (entry->d_type == DT_DIR) continue;
        snprintf(old_path, sizeof(old_path), "%s/%s", old_folder, entry->d_name);
        snprintf(new_path, sizeof(new_path), "%s/%s", new_folder, entry->d_name);
        rename(old_path, new_path);

        char message[PATH_MAX];
        snprintf(message, sizeof(message), "%s - Successfully moved to %s directory.", entry->d_name, new_folder);
        logger(message);
    }

    closedir(dir);
    return 0;
}

int delfiles(char *foldername) {
    DIR *dir;
    struct dirent *entry;
    char path[PATH_MAX];

    dir = opendir(foldername);
    if (!dir) return -1;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        snprintf(path, sizeof(path), "%s/%s", foldername, entry->d_name);
        remove(path);

        char message[PATH_MAX];
        snprintf(message, sizeof(message), "%s - Successfully deleted.", entry->d_name);
        logger(message);
    }

    closedir(dir);
    return 0;
}

int shutdown(char *processName) {
    char command[256];
    snprintf(command, sizeof(command), "pidof %s", processName);
    FILE *fp = popen(command, "r");
    if (fp == NULL) return 1;

    pid_t pid;
    if (fscanf(fp, "%d", &pid) == 1) {
        kill(pid, SIGTERM);

        char message[256];
        snprintf(message, sizeof(message), "Successfully shut off decryption process with PID %d.", pid);
        logger(message);
    }
    pclose(fp);

    return 0;
}

void logger(char *message) {
    FILE *fp = fopen("activity.log", "a");
    if (fp) {
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        char time_str[24];
        strftime(time_str, sizeof(time_str), "[%d-%m-%Y] [%H:%M:%S]", t);
        fprintf(fp, "%s - %s\n", time_str, message);
        fclose(fp);
    }
}