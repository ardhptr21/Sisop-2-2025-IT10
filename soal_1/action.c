#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/wait.h>
#include <errno.h>

// A. Downloading the Clues
void downloadAndExtract() {
    struct stat st;
    if (stat("Clues", &st) == 0 && S_ISDIR(st.st_mode)) return;

    pid_t child_pid = fork();
    if (child_pid == 0) {
        char *args[] = {"wget", "-q", "https://drive.google.com/uc?export=download&id=1xFn1OBJUuSdnApDseEczKhtNzyGekauK", "-O", "Clues.zip", NULL};
        execvp(args[0], args);
        exit(EXIT_FAILURE);
    } else if (child_pid > 0) {
        int status;
        waitpid(child_pid, &status, 0);

        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            pid_t unzip_pid = fork();
            if (unzip_pid == 0) {
                char *args[] = {"unzip", "-q", "Clues.zip", NULL};
                execvp(args[0], args);
                exit(EXIT_FAILURE);
            } else if (unzip_pid > 0) {
                int unzip_status;
                waitpid(unzip_pid, &unzip_status, 0);

                if (WIFEXITED(unzip_status) && WEXITSTATUS(unzip_status) == 0) {
                    pid_t rm_pid = fork();
                    if (rm_pid == 0) {
                        char *args[] = {"rm", "Clues.zip", NULL};
                        execvp(args[0], args);
                        exit(EXIT_FAILURE);
                    } else {
                        wait(NULL);
                    }
                }
            }
        }
    }
}

// B. Filtering the Files
void filterFiles() {
    if (mkdir("Filtered", 0755) == -1 && errno != EEXIST) return;

    const char *clueFolders[] = {"Clues/ClueA", "Clues/ClueB", "Clues/ClueC", "Clues/ClueD"};
    int numFolders = sizeof(clueFolders) / sizeof(clueFolders[0]);

    for (int i = 0; i < numFolders; i++) {
        DIR *dir = opendir(clueFolders[i]);
        if (!dir) continue;

        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

            char *filename = entry->d_name;
            char *extension = strrchr(filename, '.');

            if (extension) {
                int nameLength = extension - filename;
                char sourcePath[512], destPath[512];
                snprintf(sourcePath, sizeof(sourcePath), "%s/%s", clueFolders[i], filename);

                if (nameLength == 1 && (isalpha(filename[0]) || isdigit(filename[0]))) {
                    snprintf(destPath, sizeof(destPath), "Filtered/%s", filename);
                    pid_t mv_pid = fork();
                    if (mv_pid == 0) {
                        char *args[] = {"mv", sourcePath, destPath, NULL};
                        execvp(args[0], args);
                        exit(EXIT_FAILURE);
                    } else {
                        wait(NULL);
                    }
                } else {
                    pid_t rm_pid = fork();
                    if (rm_pid == 0) {
                        char *args[] = {"rm", sourcePath, NULL};
                        execvp(args[0], args);
                        exit(EXIT_FAILURE);
                    } else {
                        wait(NULL);
                    }
                }
            }
        }
        closedir(dir);
    }
}

// C. Combine the File Content
typedef struct {
    char name[256];
    char path[512];
    char content[1024];
} FileInfo;

int compareFileNames(const void *a, const void *b) {
    return strcmp(((FileInfo*)a)->name, ((FileInfo*)b)->name);
}

void combineFiles() {
    DIR *dir = opendir("Filtered");
    if (!dir) return;

    FileInfo digitFiles[100], alphaFiles[100];
    int digitCount = 0, alphaCount = 0;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

        char *extension = strrchr(entry->d_name, '.');
        if (extension && strcmp(extension, ".txt") == 0) {
            char filePath[512];
            snprintf(filePath, sizeof(filePath), "Filtered/%s", entry->d_name);

            FILE *file = fopen(filePath, "r");
            if (file) {
                char firstChar = entry->d_name[0];
                if (isdigit(firstChar)) {
                    strcpy(digitFiles[digitCount].name, entry->d_name);
                    strcpy(digitFiles[digitCount].path, filePath);
                    fgets(digitFiles[digitCount].content, sizeof(digitFiles[digitCount].content), file);
                    digitCount++;
                } else if (isalpha(firstChar)) {
                    strcpy(alphaFiles[alphaCount].name, entry->d_name);
                    strcpy(alphaFiles[alphaCount].path, filePath);
                    fgets(alphaFiles[alphaCount].content, sizeof(alphaFiles[alphaCount].content), file);
                    alphaCount++;
                }
                fclose(file);
            }
        }
    }

    closedir(dir);

    qsort(digitFiles, digitCount, sizeof(FileInfo), compareFileNames);
    qsort(alphaFiles, alphaCount, sizeof(FileInfo), compareFileNames);

    FILE *combinedFile = fopen("Filtered/Combined.txt", "w");
    if (!combinedFile) return;

    int maxCount = (digitCount > alphaCount) ? digitCount : alphaCount;
    for (int i = 0; i < maxCount; i++) {
        if (i < digitCount) fprintf(combinedFile, "%s", digitFiles[i].content);
        if (i < alphaCount) fprintf(combinedFile, "%s", alphaFiles[i].content);
    }

    fclose(combinedFile);

    for (int i = 0; i < digitCount; i++) unlink(digitFiles[i].path);
    for (int i = 0; i < alphaCount; i++) unlink(alphaFiles[i].path);
}

// D. Decode the file
char rot13(char c) {
    if ((c >= 'a' && c <= 'm') || (c >= 'A' && c <= 'M')) return c + 13;
    else if ((c >= 'n' && c <= 'z') || (c >= 'N' && c <= 'Z')) return c - 13;
    else return c;
}

void decodeFile() {
    FILE *combinedFile = fopen("Filtered/Combined.txt", "r");
    if (!combinedFile) return;

    FILE *decodedFile = fopen("Filtered/Decoded.txt", "w");
    if (!decodedFile) {
        fclose(combinedFile);
        return;
    }

    char c;
    while ((c = fgetc(combinedFile)) != EOF) {
        fputc(rot13(c), decodedFile);
    }

    fclose(combinedFile);
    fclose(decodedFile);
}

// E. Password Check
void passwordCheck() {
    FILE *file = fopen("Filtered/Decoded.txt", "r");
    if (!file) return;

    char correctPassword[256];
    if (!fgets(correctPassword, sizeof(correctPassword), file)) {
        fclose(file);
        return;
    }
    fclose(file);
    correctPassword[strcspn(correctPassword, "\n")] = '\0';

    char input[256];
    read(STDIN_FILENO, input, sizeof(input));
    input[strcspn(input, "\n")] = '\0';

    if (strcmp(input, correctPassword) == 0) {
    } else {
    }
}

// Main
int main(int argc, char *argv[]) {
    if (argc == 1) {
        downloadAndExtract();
    } else if (argc == 3 && strcmp(argv[1], "-m") == 0) {
        if (strcmp(argv[2], "Filter") == 0) {
            filterFiles();
        } else if (strcmp(argv[2], "Combine") == 0) {
            combineFiles();
        } else if (strcmp(argv[2], "Decode") == 0) {
            decodeFile();
        } else if (strcmp(argv[2], "Check") == 0) {
            passwordCheck();
        }
    }
    return 0;
}