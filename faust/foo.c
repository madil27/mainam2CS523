static inline int _parse_log(const char* buf, struct log_entry *entry) {
    char str_pid[4];
    if (0 < sscanf(buf, "type=%99[^ ] msg=audit(%99[^)]): %*[ a-zA-Z0-9]pid=%i uid=%i auid=%ld ses=%ld msg=\'op=%99[^ ] acct=\"%99[^\"]\" exe=\"%99[^\"]\" hostname=%99[^ ] addr=%99[^ ] terminal=%99[^ ] res=%99[^ \']\'", \
        entry->type, entry->timestamp, &(entry->pid), &(entry->uid), &(entry->auid), &(entry->ses), \
        entry->msg.op, entry->msg.acct, entry->msg.exe, entry->msg.hostname, entry->msg.addr, \
        entry->msg.terminal, entry->msg.res))
        return 0;
    else
        return 1;
}

struct msg_entry {
    char op[MSG_LEN];
    char acct[MSG_LEN];
    char exe[MSG_LEN];
    char hostname[MSG_LEN];
    char addr[MSG_LEN];
    char terminal[MSG_LEN];
    char res[MSG_LEN];
};
