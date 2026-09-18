#!/usr/bin/env python3
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request

REPO = os.environ.get("REPO", "")
BRANCH = os.environ.get("BRANCH", "main")
TOKEN = os.environ.get("GITHUB_TOKEN", "")
API = f"https://api.github.com/repos/{REPO}"
WF = "afeye.yml"


def call(method, path, data=None):
    req = urllib.request.Request(API + path, method=method)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "afeye-push-js")
    if TOKEN:
        req.add_header("Authorization", f"Bearer {TOKEN}")
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, body, timeout=30) as r:
            b = r.read()
            return json.loads(b) if b else {}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def get_queue():
    r = call("GET", f"/contents/queue/pending.json?ref={BRANCH}&t={int(time.time())}")
    if r is None:
        return {"items": []}, None
    try:
        return json.loads(base64.b64decode(r["content"])), r.get("sha")
    except Exception:
        return {"items": []}, None


def put_queue(q, sha):
    data = {
        "message": "queue: push js",
        "content": base64.b64encode(json.dumps(q).encode()).decode(),
        "branch": BRANCH,
    }
    if sha:
        data["sha"] = sha
    call("PUT", "/contents/queue/pending.json", data)


def active_run():
    r = call("GET", "/actions/runs?per_page=30")
    if not r:
        return False
    for w in r.get("workflow_runs", []):
        if w.get("path", "").endswith(WF) and w.get("status") in ("in_progress", "queued", "waiting", "pending"):
            return True
    return False


def dispatch():
    call("POST", "/dispatches", {"event_type": "afeye-js"})


def main():
    if not REPO:
        print("set REPO=owner/name (and GITHUB_TOKEN for private repos)")
        sys.exit(1)
    if len(sys.argv) < 2:
        print("usage: push-js.py '<js code>' | push-js.py script.js | cat x.js | push-js.py -")
        sys.exit(1)
    arg = sys.argv[1]
    if arg == "-":
        js = sys.stdin.read()
    elif os.path.isfile(arg):
        with open(arg) as f:
            js = f.read()
    else:
        js = arg
    if not js.strip():
        print("empty js")
        sys.exit(1)
    q, sha = get_queue()
    items = q.setdefault("items", [])
    item = {"id": f"j{int(time.time() * 1000)}", "js": js, "added": int(time.time())}
    items.append(item)
    if len(items) > 100:
        del items[:-100]
    put_queue(q, sha)
    if active_run():
        print(f"{item['id']} queued; live session will execute it within 30s")
    else:
        dispatch()
        print(f"{item['id']} queued; action dispatched, will execute on start")


if __name__ == "__main__":
    main()
