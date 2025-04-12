#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <ctype.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/wait.h> 
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>

void show_process(const char *username);
void run_daemon(const char *username);
void stop_daemon(const char *username);
void fail_user(const char *username);
void revert_user(const char *username);
void write_log(const char *process_name, const char *status);

//mendapatkan uid
uid_t get_uid_from_username(const char *username) {
    struct passwd *pwd = getpwnam(username);
    return pwd ? pwd->pw_uid : (uid_t)-1;
}

//Mengetahui semua aktivitas user
void show_process(const char *username){
    pid_t pid = fork();

    if (pid == 0) {
        char *args[] = {"ps", "-u", (char *)username, "-o", "pid,comm,%cpu,%mem", NULL};
        execvp("ps", args);
        exit(EXIT_FAILURE);
    } else if (pid > 0){
        wait(NULL);
    }
}

//menjalankan daemon
void run_daemon(const char *username) {
    write_log("daemon", "RUNNING");
    pid_t pid = fork();

    if (pid < 0) {
        exit(EXIT_FAILURE);
    }  if (pid > 0) {
        exit(EXIT_SUCCESS); 
    }

    char pid_file[64];
    snprintf(pid_file, sizeof(pid_file), "daemon_%s.pid", username);
    FILE *fp = fopen(pid_file, "w");
    if (fp) {
    fprintf(fp, "%d", getpid());
    fclose(fp);
    }

    setsid();
    if (chdir("/") < 0) exit(EXIT_FAILURE);

    fclose(stdin);
    fclose(stdout);
    fclose(stderr);

    while (1) {
        write_log("daemon", "RUNNING");
        show_process(username);
        sleep(5);
    }
}

//menghentikan daemon
void stop_daemon(const char *username) {
    char pid_file[64];
    snprintf(pid_file, sizeof(pid_file), "daemon_%s.pid", username);

    FILE *fp = fopen(pid_file, "r");
    if (!fp) {
        printf("Daemon user %s not found.\n", username);
        return;
    }

    pid_t pid;
    fscanf(fp, "%d", &pid);
    fclose(fp);

    if (kill(pid, SIGTERM) == 0) {
        printf("Daemon user %s successfuly stopped.\n", username);
        remove(pid_file); 
    } else {
        perror("Failed to stopped daemon user %s");
    }
    write_log("stop", "RUNNING");
}

//Menggagalkan semua proses user yang sedang berjalan (pakai akun dummy)
void fail_user(const char *username) {
    pid_t pid = fork();

    if (pid == 0) {
        char *args[] = {"killall", "-9", "-u", (char *)username, NULL};
        execvp("killall", args);
        exit(EXIT_FAILURE);
    } else if (pid > 0) {
        wait(NULL);
        write_log("fail", "FAILED");
        printf("Successfuly stop all %s process\n", username);
    } 
}

//revert kembali proses user 
void revert_user(const char *username) {
    pid_t pid = fork();

    if (pid == 0) {
        char *args[] = {"su", "-", (char *)username, NULL};
        execvp("su", args);
        exit(EXIT_FAILURE);
    } else if (pid > 0) {
        wait(NULL);
        write_log("revert", "RUNNING");
        printf("Successfully reverted user %s process\n", username);
    }
}


//merekam ke log
void write_log(const char *process_name, const char *status) {
    FILE *log_file = fopen("/home/asuramawaru/debugmon.log", "a");
    if (!log_file) {
        perror("Failed to open debugmon.log");
        return;
    }

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char date[32];
    char time[32];

    strftime(date, sizeof(date), "%d:%m:%Y", t);
    strftime(time, sizeof(time), "%H:%M:%S", t); 

    fprintf(log_file, "[%s]-[%s]_%s_STATUS(%s)\n", date, time, process_name, status);
    fclose(log_file);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Format: ./debugmon <fitur> <username>\n");
        return 1;
    }

    if (strcmp(argv[1], "list") == 0) {
        show_process(argv[2]);  
    } else if (strcmp(argv[1], "daemon") == 0) {
        run_daemon(argv[2]);
    } else if (strcmp(argv[1], "stop") == 0) {
        stop_daemon(argv[2]);
    } else if (strcmp(argv[1], "fail") == 0 && argc == 3) {
        fail_user(argv[2]);
    } else if (strcmp(argv[1], "revert") == 0 && argc == 3) {
        revert_user(argv[2]);
    } else {
        printf("Command not found\n");
    }

    return 0;
}
