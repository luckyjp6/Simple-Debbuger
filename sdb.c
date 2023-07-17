#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <capstone/capstone.h>

csh cs_handle;
pid_t child;
int child_stat;
struct user_regs_struct regs, anchor_regs;
char cmd[100];

int bps_idx = 0, wait_to_set = -1;
struct break_point{
    unsigned long long int addr;
    uint8_t value;
}bps[1000];
struct Backup
{
    char data[200000];
    long start_addr;
    long length;
}backups[5];
int backups_idx = 0;

void clear_bp(int idx);
int get_empty_bp();

void err_quit(char *msg);

void read_args();
void read_backups();
void write_backups();

void set_break(unsigned long long int b_addr, bool is_new);
void recover_break(int idx, bool msg);

int check_bp(unsigned long long int now);
int wait_stop();
void print_insturctions();
int do_next();

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: ./sdb [program]\n");
        return 0;
    }

    unsigned long long int entry_point; 
    unsigned long long int magic_addr;

    if((child = fork()) < 0) err_quit("fork");
    if (child == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) err_quit("ptrace traceme");
        execvp(argv[1], argv+1);
        err_quit("execvp");
    }

    /* clear bps */
    for (int i = 0; i < 1000; i++) clear_bp(i);

    /* open capstone handler */
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle) != CS_ERR_OK) {
        perror("capstone");
        return -1;
    }
    // if (ptrace(PTRACE_ATTACH, child, 0, 0) < 0) err_quit("ptrace attach");
    
    if (waitpid(child, &child_stat, 0) < 0) err_quit("waitpid");
    if (ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL) < 0) err_quit("ptrace set options");
    if (!WIFSTOPPED(child_stat)) err_quit("child not stop");

    int fd;
    char path[100] = {0}, buf[200000];
    sprintf(path, "/proc/%d/maps", child);
    fd = open(path, O_RDONLY);
    if (fd < 0) err_quit("open child maps");
    // printf("open at %d\n", fd); fflush(stdout);
    int r_len = read(fd, buf, sizeof(buf));
    if (r_len < 0) err_quit("read child maps");
    if (r_len == 0) err_quit("EOF??");
    // write(1, buf, r_len);
    char *line, *b = buf;
    while ((line = strtok_r(b, "\r\n", &b)) != NULL) {
        if ((strstr(line, "rwxp") != NULL) || (strstr(line, "rw-p") != NULL)) {
            long end_addr;
            int offset;
            char *tmp;
            // 7fff6e6cf000-7fff6e6f1000 rwxp 00000000 00:00 0     [stack]
            // get start addr
            tmp = strtok_r(line, "-", &line);
            sscanf(tmp, "%lx", &backups[backups_idx].start_addr);

            tmp = strtok_r(line, " ", &line);
            sscanf(tmp, "%lx", &end_addr);

            // add offset
            tmp = strtok_r(line, " ", &line); // "rwxp"
            tmp = strtok_r(line, " ", &line); // offset
            sscanf(tmp, "%x", &offset);
            backups[backups_idx].start_addr += offset;

            // get length
            backups[backups_idx].length = end_addr - backups[backups_idx].start_addr;

            // printf("start addr: %lx, end addr: %lx, offset: %x, length: %lx\n", backups[backups_idx].start_addr, end_addr, offset, backups[backups_idx].length);
            backups_idx++;
        }
    }

    /* start child */
    read_args();
    entry_point = regs.rip;
    printf("** program '%s' loaded. entry point 0x%llx\n", argv[1], entry_point);
    print_insturctions();
    while (true) {
        int cmd_len, now_bp;
        memset(cmd, 0, 100);

        printf("(sdb): "); fflush(stdout);
        cmd_len = read(0, cmd, 100);
        if (cmd_len < 0) err_quit("stdin");
        if (cmd_len == 0) break;

        if (memcmp(cmd, "exit", 4) == 0) break;
        else if (memcmp(cmd, "si", 2) == 0) {
            if (ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0) err_quit("single step");
            if (do_next() > 0) break; // client exit
        } else if (memcmp(cmd, "cont", 4) == 0) {
            /* single step and recover break point */
            if (ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0) err_quit("single step");
            if (wait_stop() > 0) break;
            if (wait_to_set >= 0) {
                set_break(bps[wait_to_set].addr, false);
                wait_to_set = -1;
            }

            read_args();
            int idx = check_bp(regs.rip);
            if (idx >= 0) recover_break(idx, true);
            else { if (ptrace(PTRACE_CONT, child, 0, 0) < 0) err_quit("cont"); }
            if (do_next() > 0) break; // client exit
        } else if (memcmp(cmd, "break", 5) == 0) {
            unsigned long long int b_addr;
            char *location = cmd;
            char *tmp_cmd = strtok_r(location, " ", &location);
            sscanf(location, "%llx", &b_addr);
            if (check_bp(b_addr) < 0) set_break(b_addr, true);
            else printf("** set a breakpoint at 0x%llx.\n", b_addr);
        } else if (memcmp(cmd, "anchor", 6) == 0) {
            if (ptrace(PTRACE_GETREGS, child, 0, &anchor_regs) < 0) err_quit("ptrace get regs");
            read_backups();
            printf("** dropped an anchor\n");
        } else if (memcmp(cmd, "timetravel", 10) == 0) {
            if (ptrace(PTRACE_SETREGS, child, 0, &anchor_regs) < 0) err_quit("ptrace set regs");      
            printf("** go back to the anchor point\n");
            read_args();

            if (wait_to_set >= 0) {
                set_break(bps[wait_to_set].addr, false);
                wait_to_set = -1;
            }
            
            write_backups();
            int idx = check_bp(regs.rip);
            if (idx >= 0) recover_break(idx, false);

            print_insturctions();
        } //else if (memcmp(cmd, "print_rbx", 10) == 0) {
            read_args();
            printf("rbx: %llx\n", regs.rbx);
        // }

        fflush(stdout);
    }

    cs_close(&cs_handle);
    return 0;
}


void clear_bp(int idx) {
    bps[idx].addr = -1;
    bps[idx].value = -1;

    if (idx == bps_idx && idx > 0) bps_idx -= 1;
}
int get_empty_bp() {
    return bps_idx++;

    int i;
    for (i = 0; i < bps_idx; i++) {
        if ((bps[i].addr == -1) && (bps[i].value == -1)) break;
    }
    if (i == bps_idx) bps_idx += 1;
    return i;
}

void err_quit(char *msg) {
    perror(msg);
    cs_close(&cs_handle);
    exit(-1);
}

void read_args() {
    if (ptrace(PTRACE_GETREGS, child, 0, &regs) < 0) err_quit("ptrace get regs");
}
void read_backups() {
    for (int i = 0; i < backups_idx; i++) {
        for (int offset = 0; offset < backups[i].length; offset += 8) {
            long tmp = ptrace(PTRACE_PEEKTEXT, child, backups[i].start_addr+offset);
            memcpy(backups[i].data + offset, &tmp, 8);
        }
    }
}
void write_backups() {
    for (int i = 0; i < backups_idx; i++) {
        for (int offset = 0; offset < backups[i].length; offset += 8) {
            long tmp;
            memcpy(&tmp, backups[i].data + offset, 8);
            if (ptrace(PTRACE_POKETEXT, child, backups[i].start_addr+offset, tmp) < 0) err_quit("ptrace poketext");
        }
    }
}


void set_break(unsigned long long int b_addr, bool is_new) {
    /* get original instruction */
    unsigned long int tmp_codes;
    tmp_codes = ptrace(PTRACE_PEEKTEXT, child, b_addr, 0);
    if (tmp_codes <= 0) {
        printf("Invalid break point\n");
        return;
    }

    /* recored */
    if (is_new) {
        int bp = get_empty_bp();
        bps[bp].addr = b_addr;
        bps[bp].value = tmp_codes & 0xff;
    }

    /* set 0xcc */
    if (ptrace(PTRACE_POKETEXT, child, b_addr, (tmp_codes & 0xffffffffffffff00) | 0xcc) < 0) err_quit("ptrace poketext");
   
    if (is_new) printf("** set a breakpoint at 0x%llx.\n", b_addr);
    return;
}
void recover_break(int idx, bool msg) {
    /* get current instruction */
    unsigned long int tmp_codes;
    tmp_codes = ptrace(PTRACE_PEEKTEXT, child, bps[idx].addr, 0);
    if (tmp_codes <= 0) {
        printf("Invalid break point\n");
        return;
    }

    /* recover original instruction */
    if (ptrace(PTRACE_POKETEXT, child, bps[idx].addr, (tmp_codes & 0xffffffffffffff00) | bps[idx].value) < 0) err_quit("ptrace poketext");
    if (memcmp(cmd, "cont", 4) == 0) {
        regs.rip --;
        if (ptrace(PTRACE_SETREGS, child, 0, &regs) < 0) err_quit("ptrace set regs");
    }

    if (msg) printf("** hit a breakpoint at 0x%llx\n", bps[idx].addr);

    wait_to_set = idx;
    // clear_bp(idx);
    return;
}

int check_bp(unsigned long long int now) {
    for (int i = 0; i < bps_idx; i++) {
        if ((bps[i].addr == -1) && (bps[i].value == -1)) continue;
        if (bps[i].addr == now) {
            // recover_break(i);
            return i;
        }
    }
    return -1;
}
int wait_stop() {
    
    if (waitpid(child, &child_stat, 0) < 0) err_quit("waitpid");
    if (WIFEXITED(child_stat)) {
        printf("** the target program terminated.\n");
        return 1;
    }
    if (!WIFSTOPPED(child_stat)) printf("child not stop");
    return 0;
}
void print_insturctions() {
    size_t num_ins;
    cs_insn *insns;
    uint8_t codes[100] = {0};

    for (int t = 0; t < 8; t++) {
        long tmp_codes = 0;
        tmp_codes = ptrace(PTRACE_PEEKTEXT, child, regs.rip+t*8, 0);
        // memcpy(codes+(t*8), &tmp_codes, 8);
        if (tmp_codes == 0) break;
        for (int i = 0; i < 8; i++) {
            codes[t*8+i] = tmp_codes & 0xff;
            if (codes[t*8+i] == 0xcc) {
                int idx = check_bp(regs.rip + t*8 + i);
                if (idx >= 0) codes[t*8+i] = bps[idx].value;
            }

            tmp_codes = tmp_codes >> 8;
        }
    }
    
    // if (errno == ESRCH) ??? not sure
    if ((num_ins = cs_disasm(cs_handle, codes, 64*sizeof(uint8_t), regs.rip, 0, &insns)) < 0) err_quit("cs disasm");

    if (num_ins < 5) err_quit("print ins: not enough");

    for (int i = 0; i < 5; i++) {
        if (insns[i].bytes[0] == 0) {
            printf("** the address is out of the range of the text section.\n");
            return;
        }
        printf("\t%lx: ", insns[i].address);
        for (int j = 0; j < 10; j++) {
            if (j < insns[i].size) printf("%02x ", insns[i].bytes[j]);
            else printf("   ");
        }
        printf("%-12s %s\n",insns[i].mnemonic,insns[i].op_str);
    }
    cs_free(insns, num_ins);
    return;
}
int do_next() {
    /* wait client end */
    if (wait_stop() > 0) return 1;
    if (wait_to_set >= 0) {
        set_break(bps[wait_to_set].addr, false);
        wait_to_set = -1;
    }
    
    /* get new args */
    read_args();

    int idx;
    if (memcmp(cmd, "cont", 4) == 0) idx = check_bp(regs.rip -1);
    if (memcmp(cmd, "si", 2) == 0) idx = check_bp(regs.rip);
    if (idx >= 0) recover_break(idx, true);

    print_insturctions();
    return 0;
}