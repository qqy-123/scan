"""Fresh server bootstrap: upload full tree, then run _setup.sh."""
import os

from deploy_ssh import conn, run

REMOTE = "/opt/scan"
DIRS = ["app", "rules", "tools", "web/out"]
FILES = ["requirements.txt", "_setup.sh"]


def up_tree(c, sftp, local_dir, remote_dir):
    rc, out, err = run(c, f'mkdir -p "{remote_dir}"')
    n = 0
    for name in sorted(os.listdir(local_dir)):
        if name in ("__pycache__", ".DS_Store") or name.endswith(".pyc"):
            continue
        p = os.path.join(local_dir, name)
        rp = f"{remote_dir}/{name}"
        if os.path.isdir(p):
            n += up_tree(c, sftp, p, rp)
        else:
            sftp.put(p, rp)
            n += 1
    return n


if __name__ == "__main__":
    c = conn()
    run(c, f"mkdir -p {REMOTE}")
    sftp = c.open_sftp()
    total = 0
    for f in FILES:
        sftp.put(f, f"{REMOTE}/{f}")
        print("up", f)
    for d in DIRS:
        n = up_tree(c, sftp, d, f"{REMOTE}/{d}")
        total += n
        print(f"up {d}/ -> {n} files")
    sftp.close()
    print("total uploaded:", total)

    rc, out, err = run(c, "mkdir -p /opt/scan/screenshots && "
                          "bash /opt/scan/_setup.sh", timeout=1200)
    print(out[-6000:])
    print("STDERR:", err[-1500:] if err else "")
    print("RC:", rc)
    c.close()
