#!/usr/bin/env python3
"""End-to-end test: drives sops-ls over stdio like an editor would, against
real sops + age. Usage: SOPS_AGE_KEY_FILE=... python3 e2e.py <sops-ls> <workdir>"""
import json, os, subprocess, sys, threading, queue, shutil, pathlib

BIN, WORK = sys.argv[1], pathlib.Path(sys.argv[2])


class Client:
    def __init__(self):
        self.p = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr)
        self.q, self.notes, self.id, self.docs = queue.Queue(), [], 0, {}
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        f = self.p.stdout
        while True:
            hdr = {}
            while (line := f.readline().decode()) not in ("\r\n", ""):
                k, v = line.split(":", 1); hdr[k.lower()] = v.strip()
            if not hdr: return
            self.q.put(json.loads(f.read(int(hdr["content-length"]))))

    def send(self, msg):
        b = json.dumps(msg).encode()
        self.p.stdin.write(f"Content-Length: {len(b)}\r\n\r\n".encode() + b); self.p.stdin.flush()

    def notify(self, method, params): self.send({"jsonrpc": "2.0", "method": method, "params": params})

    def request(self, method, params):
        self.id += 1; rid = self.id
        self.send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        while True:
            m = self.q.get(timeout=60)
            if m.get("id") == rid and "method" not in m: return m
            self._handle(m)

    def _handle(self, m):
        if m.get("method") == "workspace/applyEdit":       # play the editor
            for uri, edits in m["params"]["edit"]["changes"].items():
                self.docs[uri]["text"] = edits[0]["newText"]; self.change(uri)
            self.send({"jsonrpc": "2.0", "id": m["id"], "result": {"applied": True}})
        elif "id" in m and "method" in m:
            self.send({"jsonrpc": "2.0", "id": m["id"], "result": None})
        else:
            self.notes.append(m)

    def pump(self, t=0.5):
        try:
            while True: self._handle(self.q.get(timeout=t))
        except queue.Empty: pass

    def diags(self, uri):
        self.pump()
        ds = [n["params"]["diagnostics"] for n in self.notes
              if n.get("method") == "textDocument/publishDiagnostics" and n["params"]["uri"] == uri]
        return ds[-1] if ds else []

    def open(self, path, lang):
        uri = pathlib.Path(path).as_uri()
        self.docs[uri] = {"text": pathlib.Path(path).read_text(), "v": 1}
        self.notify("textDocument/didOpen", {"textDocument": {"uri": uri, "languageId": lang, "version": 1, "text": self.docs[uri]["text"]}})
        return uri

    def change(self, uri):
        d = self.docs[uri]; d["v"] += 1
        self.notify("textDocument/didChange", {"textDocument": {"uri": uri, "version": d["v"]}, "contentChanges": [{"text": d["text"]}]})

    def pos_of(self, uri, needle, delta=2):
        t = self.docs[uri]["text"]; off = t.index(needle) + delta
        line = t[:off].count("\n"); col = off - (t[:off].rfind("\n") + 1)
        return {"line": line, "character": col}

    def hover(self, uri, needle, delta=2):
        r = self.request("textDocument/hover", {"textDocument": {"uri": uri}, "position": self.pos_of(uri, needle, delta)})["result"]
        return r and r["contents"]["value"]

    def actions(self, uri, only=None):
        ctx = {"diagnostics": self.diags(uri)}
        if only: ctx["only"] = only
        r = self.request("textDocument/codeAction", {"textDocument": {"uri": uri},
              "range": {"start": {"line": 0, "character": 0}, "end": {"line": 0, "character": 0}}, "context": ctx})["result"]
        return {a["title"]: a for a in r}

    def run(self, uri, action):
        c = action["command"]
        r = self.request("workspace/executeCommand", {"command": c["command"], "arguments": c["arguments"]})
        self.pump(); return r


passed = 0
def check(name, cond, detail=""):
    global passed
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"\n     -> {detail}"))
    if not cond: sys.exit(1)
    passed += 1


c = Client()
c.request("initialize", {"processId": None, "rootUri": WORK.as_uri(), "capabilities": {"general": {"positionEncodings": ["utf-16"]}},
                         "initializationOptions": {"sops": {"timeoutSecs": 20}}})
c.notify("initialized", {})

# --- encrypted YAML: hover, metadata, inlay hints, clean diagnostics
y = WORK / "proj/secrets/app.yaml"
uri = c.open(y, "yaml")
check("encrypted yaml has no diagnostics", c.diags(uri) == [], c.diags(uri))
h = c.hover(uri, "password: ENC[", 12)
check("hover decrypts db.password", "`db.password`" in h and "s3cr3t pw" in h, h)
h = c.hover(uri, "port: ENC[", 8)
check("hover shows typed int", "5432" in h and "`int`" in h, h)
h = c.hover(uri, "sops:", 1)
check("hover on sops: shows metadata", "age1" in h and "Values:" in h, h)
check("hover on encrypted comment", "encrypted comment" in c.hover(uri, "#ENC[", 3))

acts = c.actions(uri)
check("encrypted file offers decrypt/toggle/updatekeys/rotate",
      {"SOPS: Decrypt for editing", "SOPS: Show decrypted values inline", "SOPS: Update keys from .sops.yaml", "SOPS: Rotate data key"} <= set(acts), list(acts))
c.run(uri, acts["SOPS: Show decrypted values inline"])
hints = c.request("textDocument/inlayHint", {"textDocument": {"uri": uri}, "range": {"start": {"line": 0, "character": 0}, "end": {"line": 999, "character": 0}}})["result"]
labels = [h["label"] for h in hints]
check("inlay hints show decrypted values", "🔓 admin" in labels and "🔓 s3cr3t pw" in labels and "🔓 two" in labels, labels)

# --- decrypt for editing -> session -> formatting re-encrypts with same data key
orig = c.docs[uri]["text"]
c.run(uri, c.actions(uri)["SOPS: Decrypt for editing"])
plain = c.docs[uri]["text"]
check("decrypt replaced buffer with plaintext", "password: s3cr3t pw" in plain and "sops:" not in plain, plain)
d = c.diags(uri)
check("session warning diagnostic", any(x["code"] == "decrypted-buffer" for x in d), d)
check("session offers re-encrypt + discard", {"SOPS: Re-encrypt", "SOPS: Discard changes (restore ciphertext)"} <= set(c.actions(uri)))

c.docs[uri]["text"] = plain.replace("s3cr3t pw", "n3w-p@ss"); c.change(uri)
fmt = c.request("textDocument/formatting", {"textDocument": {"uri": uri}, "options": {"tabSize": 2, "insertSpaces": True}})["result"]
cipher = fmt[0]["newText"]
check("formatting returns ciphertext", "ENC[AES256_GCM" in cipher and "n3w-p@ss" not in cipher, cipher[:200])
key_block = lambda t: t[t.index("-----BEGIN AGE"):t.index("-----END AGE")]
check("re-encryption preserved the data key", key_block(cipher) == key_block(orig))
c.docs[uri]["text"] = cipher; c.change(uri)
check("new value decrypts", "n3w-p@ss" in c.hover(uri, "password: ENC[", 12))

# --- eager code action for code_actions_on_format
c.run(uri, c.actions(uri)["SOPS: Decrypt for editing"])
eager = c.actions(uri, only=["source.sops.encrypt"])
check("eager source.sops.encrypt action carries an edit", "edit" in eager.get("SOPS: Re-encrypt", {}), eager)

# --- save with plaintext -> server re-encrypts on disk
y.write_text(c.docs[uri]["text"])           # editor writes plaintext
c.notify("textDocument/didSave", {"textDocument": {"uri": uri}, "text": c.docs[uri]["text"]})
c.pump(3)
check("didSave re-encrypted the file on disk", "ENC[AES256_GCM" in y.read_text() and "n3w-p@ss" not in y.read_text())
out = subprocess.run(["sops", "decrypt", str(y)], capture_output=True, text=True)
check("on-disk file decrypts with sops", out.returncode == 0 and "n3w-p@ss" in out.stdout, out.stderr)
c.docs[uri]["text"] = y.read_text(); c.change(uri)

# --- plaintext value inside encrypted file
c.docs[uri]["text"] = c.docs[uri]["text"].replace("list:\n", "leak: hunter2\nlist:\n"); c.change(uri)
d = c.diags(uri)
check("plaintext value warning", any(x["code"] == "plaintext-value" and "`leak`" in x["message"] for x in d), d)
check("_unencrypted suffix not flagged", not any("api_key_unencrypted" in x["message"] for x in d))

# --- tampered file -> MAC mismatch surfaced on open
t = WORK / "proj/secrets/tampered.yaml"
t.write_text(y.read_text().replace("api_key_unencrypted: visible", "api_key_unencrypted: changed"))
turi = c.open(t, "yaml"); c.pump(3)
d = c.diags(turi)
check("MAC mismatch diagnostic", any(x["code"] == "decrypt-failed" and "MAC mismatch" in x["message"] for x in d), d)

# --- plaintext file that should be encrypted -> quick fix encrypts via .sops.yaml
p = WORK / "proj/secrets/new.yaml"; p.write_text("token: abc\n")
puri = c.open(p, "yaml")
d = c.diags(puri)
check("should-be-encrypted warning", any(x["code"] == "should-be-encrypted" for x in d), d)
acts = c.actions(puri)
qa = acts["SOPS: Encrypt file using .sops.yaml"]
check("encrypt quick fix is preferred quickfix", qa["kind"] == "quickfix" and qa.get("isPreferred"), qa)
c.run(puri, qa)
check("new file encrypted via creation rules", "ENC[AES256_GCM" in c.docs[puri]["text"] and "age1" in c.docs[puri]["text"])
check("diagnostic cleared", c.diags(puri) == [], c.diags(puri))

# --- JSON / dotenv / INI hover
for fname, lang, needle, delta, expect in [
        ("app.enc.json", "json", '"n": "ENC[', 8, "3"),
        ("app.enc.env", "dotenv", "DB_PASS=ENC[", 10, "multi word"),
        ("app.enc.ini", "ini", "pass = ENC[", 9, "hunter2")]:
    u = c.open(WORK / fname, lang)
    h = c.hover(u, needle, delta)
    check(f"{lang} hover decrypts", h and expect in h, h)

# --- invalid plaintext must fail cleanly (no sops editor loop)
c.run(uri, c.actions(uri)["SOPS: Decrypt for editing"])
c.docs[uri]["text"] = "a: [unclosed\n"; c.change(uri)
r = c.request("textDocument/formatting", {"textDocument": {"uri": uri}, "options": {"tabSize": 2, "insertSpaces": True}})
check("invalid YAML rejected before sops", "error" in r and "invalid YAML" in r["error"]["message"], r)
c.run(uri, c.actions(uri)["SOPS: Discard changes (restore ciphertext)"])
check("discard restores ciphertext", "ENC[AES256_GCM" in c.docs[uri]["text"])

print(f"\nall {passed} checks passed")
c.request("shutdown", None); c.notify("exit", None)
