"""Deploy to scan server: upload changed app files + frontend dist, restart."""
import os
import sys

from deploy_ssh import conn, run

FILES = [
    "app/store.py", "app/main.py", "app/exposure.py",
    "app/fingerprint.py", "app/pipeline.py", "app/probe.py",
    "rules/nuclei_tech.json",
]
import os.path
DIST = "web/out" if os.path.isdir("web/out") else "frontend/dist"
REMOTE = "/opt/scan"


def up(sftp, local, remote):
    sftp.put(local, remote)


def up_tree(sftp, local_dir, remote_dir):
    run(c, f'mkdir -p "{remote_dir}"')
    for name in os.listdir(local_dir):
        p = os.path.join(local_dir, name)
        rp = f"{remote_dir}/{name}"
        if os.path.isdir(p):
            up_tree(sftp, p, rp)
        else:
            up(sftp, p, rp)


if __name__ == "__main__":
    c = conn()
    sftp = c.open_sftp()
    for f in FILES:
        if os.path.exists(f):
            up(sftp, f, f"{REMOTE}/{f}")
            print("up", f)
    run(c, f"rm -rf {REMOTE}/web/out")          # drop stale Next export chunks
    up_tree(sftp, DIST, f"{REMOTE}/web/out")
    print("up", DIST)
    sftp.close()
    rc, out, err = run(c, "systemctl restart scan && sleep 2 && "
                         "systemctl is-active scan && curl -s -o /dev/null "
                         "-w '%{http_code}' http://127.0.0.1:8000/")
    print(out, err, "rc", rc)
    c.close()
