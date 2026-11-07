"""解密数据库、导出消息 / 图片 / 头像，生成可双击打开的查看器。"""
from __future__ import annotations

import datetime
import glob
import hashlib
import html
import json
import os
import re
import shutil
import sqlite3
import sys
import urllib.request

from compression import zstd

import wxcore

# ---- b23.tv 短链解析 ----
_B23_CACHE: dict[str, str] = {}


def resolve_short_url(url: str) -> str:
    """把 b23.tv 短链还原成干净的 B 站链接；失败则原样返回。"""
    if "b23.tv" not in url:
        return url
    if url in _B23_CACHE:
        return _B23_CACHE[url]
    out = url
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 Chrome/120 Mobile Safari/537.36"})
        final = urllib.request.urlopen(req, timeout=12).geturl()
        m = re.search(r"(BV[0-9A-Za-z]{10})", final)
        out = "https://www.bilibili.com/video/" + m.group(1) if m else final.split("?")[0]
        out = out.replace("://m.bilibili.com/", "://www.bilibili.com/")
    except Exception:
        pass
    _B23_CACHE[url] = out
    return out


def _res(rel: str) -> str:
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, rel)

TYPE = {1: "text", 3: "image", 34: "voice", 43: "video", 42: "card", 47: "sticker",
        48: "location", 49: "link", 50: "voip", 10000: "system", 11000: "system"}


def _s(v):
    return v.decode("utf-8", "replace") if isinstance(v, bytes) else (v or "")


def _unz(b):
    if b and b[:4] == b"\x28\xb5\x2f\xfd":
        try:
            return zstd.decompress(b)
        except Exception:
            return b
    return b


def _attr(x, n):
    m = re.search(n + r'="([^"]*)"', x)
    return html.unescape(m.group(1)) if m else ""


def _tag(x, n):
    m = re.search(r"<" + n + r">(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</" + n + ">", x, re.S)
    return html.unescape(m.group(1)).strip() if m else ""


def _ro(p):
    c = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
    c.text_factory = bytes
    return c


def decrypt_account(account, workdir, log=print):
    """调用内置 wcdb-key-tool 扫内存拿密钥，再用 cryptography 自行解库。"""
    os.makedirs(workdir, exist_ok=True)
    old = os.getcwd()
    os.chdir(workdir)
    try:
        import vendor.wcdb_tool as wt
        ns = type("A", (), {"db_dir": account["db"], "output": "all_keys.json", "decrypt": False})()
        try:
            wt.cmd_extract(ns)
        except SystemExit:
            pass
        except Exception as e:
            log(f"  扫描出错：{e}")
        keys = {}
        kp = os.path.join(workdir, "all_keys.json")
        if os.path.exists(kp):
            try:
                keys = json.load(open(kp, encoding="utf-8"))
            except Exception:
                pass
        if not keys:
            return None, {}
        out = os.path.join(workdir, "decrypted")
        n = decrypt_databases(account["db"], keys, out, log)
        log(f"  解密 {n} 个库")
        return (out if n else None), keys
    finally:
        os.chdir(old)


def decrypt_databases(db_dir, keys, out_dir, log=print):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    page = 4096
    n = 0
    for rel, info in keys.items():
        src = os.path.join(db_dir, rel)
        if not os.path.exists(src):
            continue
        try:
            key = bytes.fromhex(info["enc_key"])
        except Exception:
            continue
        with open(src, "rb") as f:
            data = f.read()
        if len(data) < page or len(data) % page:
            continue
        buf = bytearray()
        for i in range(0, len(data), page):
            pg = data[i:i + page]
            iv = pg[4016:4032]
            if i == 0:
                dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor().update(pg[16:4016])
                buf += b"SQLite format 3\x00" + dec + b"\x00" * 80
            else:
                dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor().update(pg[:4016])
                buf += dec + b"\x00" * 80
        dst = os.path.join(out_dir, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "wb") as f:
            f.write(buf)
        n += 1
    return n


def real_self_id(account, decrypted):
    """账号目录名是 wxid_xxx_hash 形式，真实 wxid 要去掉末尾哈希。"""
    base = re.sub(r"_[0-9a-fA-F]{4}$", "", account["id"])
    names = set()
    for dbp in glob.glob(os.path.join(decrypted, "message", "message_*.db")):
        if dbp.endswith(("message_fts.db", "message_resource.db")):
            continue
        try:
            c = _ro(dbp)
            names |= {_s(x) for (x,) in c.execute("select user_name from Name2Id")}
            c.close()
        except Exception:
            pass
    if base in names:
        return base
    for n in names:
        if n and (n == base or n.startswith(base) or base.startswith(n)):
            return n
    return base


def _load_contacts(decrypted):
    contacts = {}
    cp = os.path.join(decrypted, "contact", "contact.db")
    if not os.path.exists(cp):
        return contacts
    c = _ro(cp)
    cols = [r[1].decode() for r in c.execute("pragma table_info(contact)")]
    for row in c.execute("select * from contact"):
        d = dict(zip(cols, row))
        u = _s(d.get("username"))
        if u:
            contacts[u] = {"nick": _s(d.get("nick_name")), "remark": _s(d.get("remark"))}
    c.close()
    return contacts


def _export_avatars(decrypted, media):
    avatars = {}
    hp = os.path.join(decrypted, "head_image", "head_image.db")
    if not os.path.exists(hp):
        return avatars
    c = _ro(hp)
    for u, _m, buf in c.execute("select username, md5, image_buffer from head_image"):
        u = _s(u)
        if not buf:
            continue
        ext = ("png" if buf[:4] == b"\x89PNG" else "jpg" if buf[:3] == b"\xff\xd8\xff"
               else "gif" if buf[:3] == b"GIF" else "bin")
        fn = u.replace("/", "_").replace("\\", "_") + "." + ext
        with open(os.path.join(media, "avatars", fn), "wb") as f:
            f.write(buf)
        avatars[u] = "media/avatars/" + fn
    c.close()
    return avatars


def _collect(decrypted, contacts, self_id, log):
    def disp(u):
        if not u:
            return "系统"
        d = contacts.get(u, {})
        return d.get("remark") or d.get("nick") or u

    dbs = [d for d in sorted(glob.glob(os.path.join(decrypted, "message", "message_*.db")), reverse=True)
           if not d.endswith(("message_fts.db", "message_resource.db"))]
    msgs = {}
    seen = set()
    for dbp in dbs:
        try:
            con = _ro(dbp)
            cur = con.cursor()
            name2id = {rid: _s(nm) for rid, nm in cur.execute("select rowid, user_name from Name2Id")}
            md5map = {}
            for nm in name2id.values():
                if nm:
                    md5map[hashlib.md5(nm.encode()).hexdigest()] = nm
            tables = [r[0].decode() for r in cur.execute(
                "select name from sqlite_master where type='table' and name like 'Msg_%'")]
        except Exception as e:
            log(f"  跳过 {os.path.basename(dbp)}：{e}")
            continue
        for t in tables:
            conv = md5map.get(t[4:], t)
            try:
                rows = cur.execute(f'select local_id, server_id, local_type, real_sender_id, create_time, '
                                   f'message_content, packed_info_data from "{t}" order by sort_seq').fetchall()
            except Exception:
                continue
            for (lid, sid, lt, rid, ts, mc, pk) in rows:
                base = lt & 0xFFFF
                text = _s(_unz(mc))
                if conv.endswith("@chatroom") and "\n" in text:
                    head, rest = text.split("\n", 1)
                    if len(head) < 64 and (head.startswith("wxid_") or "@" in head):
                        text = rest
                sender = name2id.get(rid, "")
                kind = TYPE.get(base, f"type_{base}")
                key = (conv, sender, ts, kind, text[:48])
                if key in seen:
                    continue
                seen.add(key)
                m = {"id": lid, "sid": sid, "ts": ts,
                     "time": datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S"),
                     "sender": sender, "sender_name": disp(sender), "type": kind,
                     "mine": sender == self_id}
                if kind == "text":
                    m["text"] = text
                elif kind == "link":
                    apptype = _tag(text, "type")
                    if apptype == "57" or "<refermsg>" in text:
                        ref = re.search(r"<refermsg>(.*?)</refermsg>", text, re.S)
                        rb = ref.group(1) if ref else ""
                        qt = _tag(rb, "content")
                        if qt.lstrip().startswith("<"):
                            qt = "[非文本消息]"
                        m["type"] = "quote"
                        m["text"] = _tag(text, "title") or _tag(text, "des")
                        m["q"] = {"name": _tag(rb, "displayname"), "text": qt,
                                  "sid": _tag(rb, "svrid"), "time": _tag(rb, "createtime")}
                    else:
                        appinfo = re.search(r"<appinfo>(.*?)</appinfo>", text, re.S)
                        m.update({"title": _tag(text, "title") or "[链接]", "des": _tag(text, "des"),
                                  "url": resolve_short_url(_tag(text, "url")),
                                  "appname": _tag(appinfo.group(1), "appname") if appinfo else ""})
                elif kind == "image":
                    m.update({"w": int(_attr(text, "cdnthumbwidth") or 0),
                              "h": int(_attr(text, "cdnthumbheight") or 0)})
                    mo = re.search(rb"\x22\x20([0-9a-f]{32})", pk or b"")
                    if mo:
                        m["md5"] = mo.group(1).decode()
                elif kind == "video":
                    m.update({"w": int(_attr(text, "cdnthumbwidth") or 0),
                              "h": int(_attr(text, "cdnthumbheight") or 0),
                              "len": _attr(text, "playlength")})
                elif kind == "sticker":
                    m["md5"] = _attr(text, "md5")
                elif kind == "system":
                    m["text"] = re.sub(r"<[^>]+>", "", text).strip()
                elif kind == "card":
                    m["text"] = _attr(text, "nickname") or "[名片]"
                msgs.setdefault(conv, []).append(m)
        con.close()
    for conv in msgs:
        msgs[conv].sort(key=lambda x: x["ts"])
    return msgs, disp


def _merge_data(old, new):
    """补充模式：把新数据合并进旧数据。"""
    msgs = {}
    for conv, lst in (old.get("messages") or {}).items():
        msgs[conv] = list(lst)
    added = 0
    for conv, lst in (new.get("messages") or {}).items():
        cur = msgs.setdefault(conv, [])
        sids = {m.get("sid") for m in cur if m.get("sid")}
        keys = {(m.get("sender"), m.get("ts"), m.get("type"), (m.get("text") or "")[:48]) for m in cur}
        for m in lst:
            sid = m.get("sid")
            k = (m.get("sender"), m.get("ts"), m.get("type"), (m.get("text") or "")[:48])
            if (sid and sid in sids) or k in keys:
                continue
            cur.append(m)
            keys.add(k)
            if sid:
                sids.add(sid)
            added += 1
        cur.sort(key=lambda x: x.get("ts") or 0)

    names = {c["id"]: c.get("name") for c in (old.get("conversations") or [])}
    names.update({c["id"]: c.get("name") for c in (new.get("conversations") or [])})

    convs = []
    for conv, lst in msgs.items():
        if not lst:
            continue
        convs.append({"id": conv, "name": names.get(conv) or conv,
                      "is_group": conv.endswith("@chatroom"),
                      "count": len(lst), "first": lst[0].get("time", ""), "last": lst[-1].get("time", "")})
    convs.sort(key=lambda c: c["count"], reverse=True)

    avatars = dict(old.get("avatars") or {})
    avatars.update(new.get("avatars") or {})
    out = dict(new)
    out["avatars"] = avatars
    out["messages"] = msgs
    out["conversations"] = convs
    out["added"] = added
    return out


def build_export(account, decrypted, outdir, image_key, log=print, merge_old=None):
    media = os.path.join(outdir, "media")
    os.makedirs(os.path.join(media, "avatars"), exist_ok=True)
    os.makedirs(os.path.join(media, "img"), exist_ok=True)

    contacts = _load_contacts(decrypted)
    avatars = _export_avatars(decrypted, media)
    log(f"  头像 {len(avatars)} 个 · 联系人 {len(contacts)} 条")

    self_id = real_self_id(account, decrypted)
    log(f"  本机账号：{self_id}")
    msgs, disp = _collect(decrypted, contacts, self_id, log)
    total = sum(len(v) for v in msgs.values())
    log(f"  会话 {len(msgs)} 个 · 消息 {total} 条")

    # 图片
    dat_index = {}
    for p in glob.glob(os.path.join(account["dir"], "msg", "attach", "*", "*", "Img", "*.dat")):
        md5 = os.path.basename(p).split("_")[0].replace(".dat", "")
        dat_index.setdefault(md5, p)
    img_done = {}
    if image_key:
        for md5, p in dat_index.items():
            try:
                out, fmt = wxcore.decrypt_dat(p, image_key)
            except Exception:
                continue
            if not out or fmt not in ("jpg", "png", "gif", "webp"):
                continue
            fn = md5 + "." + fmt
            with open(os.path.join(media, "img", fn), "wb") as f:
                f.write(out)
            img_done[md5] = "media/img/" + fn
        log(f"  图片解出 {len(img_done)} 张")

    for lst in msgs.values():
        for m in lst:
            if m["type"] == "image":
                src = img_done.get(m.get("md5") or "")
                if src:
                    m["src"] = src

    convs = []
    for conv, lst in msgs.items():
        if lst:
            convs.append({"id": conv, "name": disp(conv), "is_group": conv.endswith("@chatroom"),
                          "count": len(lst), "first": lst[0]["time"], "last": lst[-1]["time"]})
    convs.sort(key=lambda c: c["count"], reverse=True)

    data = {"account": self_id, "self_id": self_id, "self_name": disp(self_id),
            "generated": datetime.datetime.now().isoformat(timespec="seconds"),
            "avatars": avatars, "conversations": convs, "messages": msgs}
    if merge_old:
        before = sum(len(v) for v in (merge_old.get("messages") or {}).values())
        data = _merge_data(merge_old, data)
        log(f"  补充模式：原有 {before} 条，新增 {data.get('added', 0)} 条，共 "
            f"{sum(c['count'] for c in data['conversations'])} 条")
    with open(os.path.join(outdir, "data.json"), "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    with open(os.path.join(outdir, "data.bundle.js"), "w", encoding="utf-8") as f:
        f.write("window.__WX_DATA__=" + json.dumps(data, ensure_ascii=False, separators=(",", ":")) + ";")

    # 表情图片 + 映射
    es = _res("emoji")
    if os.path.isdir(es):
        try:
            shutil.copytree(es, os.path.join(outdir, "WechatEmoji"), dirs_exist_ok=True)
            ej = _res("emoji.js")
            if os.path.exists(ej):
                shutil.copy2(ej, os.path.join(outdir, "emoji.js"))
            log(f"  表情图片 {len(os.listdir(es))} 个")
        except Exception as e:
            log(f"  表情复制失败：{e}")
    return data
