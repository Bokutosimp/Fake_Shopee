# ShopStack web user login profile.
# INTENTIONALLY a breadcrumb: on login / `su -l`, emit a stderr notice naming
# functionbin to nudge toward the SUID privesc. It does NOT reveal the answer
# (`-x /root/root.txt`). This is a plain shell profile line, NOT a PAM hook.
[ -x /usr/local/bin/functionbin ] && echo "notice: functionbin present; run 'functionbin' for usage" 1>&2
