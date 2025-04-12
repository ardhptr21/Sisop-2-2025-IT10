#define _DEFAULT_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define ZIP_FILE "Clues.zip"
#define ZIP_URL "https://drive.usercontent.google.com/u/0/uc?id=1xFn1OBJUuSdnApDseEczKhtNzyGekauK&export=download"

int is_valid_file(const char *filename) {
    return strlen(filename) == 5 && isalnum(filename[0]) && strcmp(filename + 1, ".txt") == 0;
}

int run_command(const char *cmd, char *const argv[]) {
    pid_t pid = fork();
    if (pid == 0) {
        execvp(cmd, argv);
        perror("exec failed");
        exit(EXIT_FAILURE);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        return WIFEXITED(status) && WEXITSTATUS(status) == 0;
    } else {
        perror("fork failed");
        return 0;
    }
}

// A. Downloading the Clues
void download_and_unzip() {
    struct stat st = {0};

    if (stat("Clues", &st) == 0 && S_ISDIR(st.st_mode)) return;

    printf("Mengunduh Clues.zip...\n");
    char *wget_args[] = {"wget", "-q", "-O", ZIP_FILE, ZIP_URL, NULL};
    if (!run_command("wget", wget_args)) {
        fprintf(stderr, "Gagal mengunduh Clues.zip\n");
        return;
    }

    printf("Ekstrak Clues.zip...\n");
    char *unzip_args[] = {"unzip", "-q", ZIP_FILE, NULL};
    if (!run_command("unzip", unzip_args)) {
        fprintf(stderr, "Gagal mengekstrak Clues.zip\n");
        return;
    }

    remove(ZIP_FILE);
    printf("Download dan ekstrak selesai.\n");
}

// B. Filtering the Files
void filter_files() {
    DIR *dir;
    struct dirent *entry;

    mkdir("Filtered", 0755);
    const char *subdirs[] = {"Clues/ClueA", "Clues/ClueB", "Clues/ClueC", "Clues/ClueD"};

    for (int i = 0; i < 4; ++i) {
        dir = opendir(subdirs[i]);
        if (!dir) continue;

        char path[512];
        while ((entry = readdir(dir))) {
            if (is_valid_file(entry->d_name)) {
                snprintf(path, sizeof(path), "%s/%s", subdirs[i], entry->d_name);
                char dest[512];
                snprintf(dest, sizeof(dest), "Filtered/%s", entry->d_name);
                rename(path, dest);
            } else if (entry->d_type == DT_REG) {
                snprintf(path, sizeof(path), "%s/%s", subdirs[i], entry->d_name);
                remove(path);
            }
        }
        closedir(dir);
    }

    printf("Filtering selesai. File disimpan di folder Filtered.\n");
}

int cmp(const void *a, const void *b) {
    return strcmp(*(const char **)a, *(const char **)b);
}

// C. Combine the File Content
void combine_files() {
    DIR *dir = opendir("Filtered");
    struct dirent *entry;
    char *numbers[100], *letters[100];
    int n_count = 0, l_count = 0;

    if (!dir) {
        fprintf(stderr, "Folder Filtered tidak ditemukan.\n");
        return;
    }

    while ((entry = readdir(dir))) {
        if (is_valid_file(entry->d_name)) {
            if (isdigit(entry->d_name[0]))
                numbers[n_count++] = strdup(entry->d_name);
            else if (isalpha(entry->d_name[0]))
                letters[l_count++] = strdup(entry->d_name);
        }
    }
    closedir(dir);

    qsort(numbers, n_count, sizeof(char *), cmp);
    qsort(letters, l_count, sizeof(char *), cmp);

    FILE *out = fopen("Combined.txt", "w");
    if (!out) {
        perror("Gagal membuat Combined.txt");
        return;
    }

    int ni = 0, li = 0;
    while (ni < n_count || li < l_count) {
        if (ni < n_count) {
            char path[256];
            snprintf(path, sizeof(path), "Filtered/%s", numbers[ni++]);
            FILE *f = fopen(path, "r");
            if (f) {
                int c;
                while ((c = fgetc(f)) != EOF) fputc(c, out);
                fclose(f);
            }
            remove(path);
        }
        if (li < l_count) {
            char path[256];
            snprintf(path, sizeof(path), "Filtered/%s", letters[li++]);
            FILE *f = fopen(path, "r");
            if (f) {
                int c;
                while ((c = fgetc(f)) != EOF) fputc(c, out);
                fclose(f);
            }
            remove(path);
        }
    }

    fclose(out);
    printf("Isi file telah digabung ke Combined.txt\n");

    for (int i = 0; i < n_count; i++) free(numbers[i]);
    for (int i = 0; i < l_count; i++) free(letters[i]);
}

// D. Decode the file
void rot13_decode() {
    FILE *in = fopen("Combined.txt", "r");
    FILE *out = fopen("Decoded.txt", "w");
    if (!in || !out) {
        perror("Gagal membuka Combined.txt atau membuat Decoded.txt");
        return;
    }

    int c;
    while ((c = fgetc(in)) != EOF) {
        if (isalpha(c)) {
            if ((c >= 'a' && c <= 'm') || (c >= 'A' && c <= 'M'))
                c += 13;
            else
                c -= 13;
        }
        fputc(c, out);
    }

    fclose(in);
    fclose(out);
    printf("Decode ROT13 selesai. Output disimpan di Decoded.txt\n");
}

// E: Password Check
void password_check() {
    FILE *file = fopen("Decoded.txt", "r");
    if (!file) {
        fprintf(stderr, "Decoded.txt tidak ditemukan.\n");
        return;
    }

    char correct_pass[256];
    if (!fgets(correct_pass, sizeof(correct_pass), file)) {
        fclose(file);
        fprintf(stderr, "Gagal membaca password.\n");
        return;
    }
    fclose(file);
    correct_pass[strcspn(correct_pass, "\n")] = '\0';

    char input[256];
    printf("Masukkan password: ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = '\0';

    if (strcmp(correct_pass, input) == 0) {
        printf("Password benar! Kamu berhasil membuka pintu Cyrus!\n");
    } else {
        printf("Password salah. Coba lagi!\n");
    }
}

// Tambahan fitur HELP
void print_help() {
    printf("./action -m [command]\n");
    printf(" Available commands\n");
    printf("     Filter\n");
    printf("     Combine\n");
    printf("     Decode\n");
    printf("     Check\n");
}

// Main
int main(int argc, char *argv[]) {
    if (argc == 1) {
        download_and_unzip();
        print_help();
    } else if (argc == 3 && strcmp(argv[1], "-m") == 0) {
        if (strcmp(argv[2], "Filter") == 0) {
            filter_files();
        } else if (strcmp(argv[2], "Combine") == 0) {
            combine_files();
        } else if (strcmp(argv[2], "Decode") == 0) {
            rot13_decode();
        } else if (strcmp(argv[2], "Check") == 0) {
            password_check();
        } else {
            print_help();  // Command tidak dikenali
        }
    } else {
        print_help();  // Format argumen salah
    }

    return 0;
}