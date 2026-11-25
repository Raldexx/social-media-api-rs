#!/usr/bin/env python3
"""
End-to-end check of a running server. Uses only the Python standard library.

    python smoke_test.py                       # most checks
    python smoke_test.py --admin-email a@b.c --admin-password 'Secret123'
                                               # + role / permission checks (needs a superuser)

Make an admin first (the server has no endpoint for that on purpose):
    UPDATE users SET is_superuser = TRUE WHERE email = 'a@b.c';
"""
import argparse
import json
import random
import string
import sys
import urllib.error
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument("--base", default="http://127.0.0.1:8000")
parser.add_argument("--admin-email")
parser.add_argument("--admin-password")
args = parser.parse_args()

passed = failed = 0


def call(method, path, body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(args.base + path, data=data, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req) as r:
            raw, status = r.read(), r.status
    except urllib.error.HTTPError as e:
        raw, status = e.read(), e.code
    try:
        return status, json.loads(raw) if raw else None
    except ValueError:
        return status, raw.decode(errors="replace")


def check(name, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
        print(f"  ok    {name}")
    else:
        failed += 1
        print(f"  FAIL  {name}  {detail}")


def expect(name, got, want_status, extra=True):
    status, body = got
    check(name, status == want_status and bool(extra), f"(got {status}: {body})")
    return body


suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
PW = "Passw0rdOK"


def register(name):
    status, body = call(
        "POST",
        "/api/v1/auth/register",
        {"username": f"{name}_{suffix}", "email": f"{name}_{suffix}@example.com", "password": PW},
    )
    assert status == 201, (status, body)
    return body


print("== basics")
expect("GET / works", call("GET", "/"), 200)
status, _ = call("GET", "/docs")
check("Swagger UI /docs works", status == 200, f"(got {status})")
status, body = call("GET", "/docs/openapi.json")
check("OpenAPI lists the endpoints", status == 200 and "/api/v1/posts" in json.dumps(body))

print("== register / login")
alice = register("alice")
A_NAME, A_EMAIL = f"alice_{suffix}", f"alice_{suffix}@example.com"
check("register returns both tokens", bool(alice["access_token"] and alice["refresh_token"]))
expect("duplicate username -> 400", call("POST", "/api/v1/auth/register",
       {"username": A_NAME, "email": "other@example.com", "password": PW}), 400)
expect("duplicate email -> 400", call("POST", "/api/v1/auth/register",
       {"username": "other_" + suffix, "email": A_EMAIL, "password": PW}), 400)
expect("weak password (no digit) -> 422", call("POST", "/api/v1/auth/register",
       {"username": "weak_" + suffix, "email": "weak@example.com", "password": "NoDigitsHere"}), 422)
expect("bad username chars -> 422", call("POST", "/api/v1/auth/register",
       {"username": "bad name!", "email": "bad@example.com", "password": PW}), 422)
expect("bad email -> 422", call("POST", "/api/v1/auth/register",
       {"username": "bademail_" + suffix, "email": "not-an-email", "password": PW}), 422)
login = expect("login ok", call("POST", "/api/v1/auth/login", {"email": A_EMAIL, "password": PW}), 200)
expect("wrong password -> 401", call("POST", "/api/v1/auth/login", {"email": A_EMAIL, "password": "Wrong123x"}), 401)
expect("unknown email -> 401", call("POST", "/api/v1/auth/login", {"email": "nobody@example.com", "password": PW}), 401)
A_TOKEN, A_REFRESH = login["access_token"], login["refresh_token"]

print("== tokens")
me = expect("GET /users/me with access token", call("GET", "/api/v1/users/me", token=A_TOKEN), 200)
check("me has the default 'user' role", me and me["role"] == "user")
expect("no token -> 401", call("GET", "/api/v1/users/me"), 401)
expect("garbage token -> 401", call("GET", "/api/v1/users/me", token="abc.def.ghi"), 401)
expect("refresh token cannot be used as access token -> 401",
       call("GET", "/api/v1/users/me", token=A_REFRESH), 401)
expect("access token cannot be used to refresh -> 401",
       call("POST", "/api/v1/auth/refresh", {"refresh_token": A_TOKEN}), 401)
new = expect("refresh works", call("POST", "/api/v1/auth/refresh", {"refresh_token": A_REFRESH}), 200)
expect("new access token works", call("GET", "/api/v1/users/me", token=new["access_token"]), 200)
expect("logout", call("POST", "/api/v1/auth/logout"), 200)

print("== profile")
call("PUT", "/api/v1/users/me", {"full_name": "Alice Wonder"}, A_TOKEN)
upd = expect("update only bio", call("PUT", "/api/v1/users/me", {"bio": "hello"}, A_TOKEN), 200)
check("full_name was kept", upd and upd["full_name"] == "Alice Wonder" and upd["bio"] == "hello")
expect("bio too long -> 422", call("PUT", "/api/v1/users/me", {"bio": "x" * 501}, A_TOKEN), 422)
pub = expect("public profile", call("GET", f"/api/v1/users/{A_NAME.upper()}"), 200)
check("public profile hides email", pub and "email" not in pub)
expect("unknown profile -> 404", call("GET", "/api/v1/users/nobody_" + suffix), 404)
expect("stats by id", call("GET", f"/api/v1/users/{me['id']}/stats"), 200)
expect("my stats", call("GET", "/api/v1/users/me/stats", token=A_TOKEN), 200)
found = expect("search finds alice", call("GET", f"/api/v1/users/search?q=Alice_{suffix}"), 200)
check("search result contains alice", found and any(u["username"] == A_NAME for u in found))
found = expect("search for '%' is literal", call("GET", "/api/v1/users/search?q=%25"), 200)
check("'%' does not match everyone", found == [])
expect("search limit=0 -> 422", call("GET", "/api/v1/users/search?q=a&limit=0"), 422)

print("== change password")
expect("wrong old password -> 400", call("PUT", "/api/v1/users/me/password",
       {"old_password": "Nope1234x", "new_password": "NewPassw0rd"}, A_TOKEN), 400)
expect("weak new password -> 422", call("PUT", "/api/v1/users/me/password",
       {"old_password": PW, "new_password": "short"}, A_TOKEN), 422)
expect("change password", call("PUT", "/api/v1/users/me/password",
       {"old_password": PW, "new_password": "NewPassw0rd"}, A_TOKEN), 200)
expect("old password stops working", call("POST", "/api/v1/auth/login", {"email": A_EMAIL, "password": PW}), 401)
expect("new password works", call("POST", "/api/v1/auth/login", {"email": A_EMAIL, "password": "NewPassw0rd"}), 200)

bob, carol = register("bob"), register("carol")
B_NAME, C_NAME = f"bob_{suffix}", f"carol_{suffix}"
B_TOKEN, C_TOKEN = bob["access_token"], carol["access_token"]

print("== posts")
expect("post without login -> 401", call("POST", "/api/v1/posts", {"content": "hi"}), 401)
expect("empty post -> 422", call("POST", "/api/v1/posts", {"content": "   "}, A_TOKEN), 422)
expect("1001 chars -> 422", call("POST", "/api/v1/posts", {"content": "x" * 1001}, A_TOKEN), 422)
post = expect("create post", call("POST", "/api/v1/posts", {"content": "first post"}, A_TOKEN), 201)
POST_ID = post["id"]
check("post has author", post["author_username"] == A_NAME and post["likes_count"] == 0)
expect("get post", call("GET", f"/api/v1/posts/{POST_ID}"), 200)
expect("unknown post -> 404", call("GET", "/api/v1/posts/999999999"), 404)
lst = expect("list posts", call("GET", "/api/v1/posts?limit=5"), 200)
check("list contains the post", lst and any(p["id"] == POST_ID for p in lst))
expect("list limit=1000 -> 422", call("GET", "/api/v1/posts?limit=1000"), 422)
up = expect("user's posts", call("GET", f"/api/v1/users/{A_NAME}/posts"), 200)
check("user's posts contains the post", up and [p["id"] for p in up] == [POST_ID])
me = call("GET", "/api/v1/users/me", token=A_TOKEN)[1]
check("posts_count is 1", me["posts_count"] == 1, me)

print("== likes")
expect("like without login -> 401", call("POST", f"/api/v1/posts/{POST_ID}/like"), 401)
liked = expect("bob likes", call("POST", f"/api/v1/posts/{POST_ID}/like", token=B_TOKEN), 200)
check("likes_count is 1", liked and liked["likes_count"] == 1)
expect("like twice -> 409", call("POST", f"/api/v1/posts/{POST_ID}/like", token=B_TOKEN), 409)
un = expect("bob unlikes", call("DELETE", f"/api/v1/posts/{POST_ID}/like", token=B_TOKEN), 200)
check("likes_count back to 0", un and un["likes_count"] == 0)
expect("unlike twice -> 404", call("DELETE", f"/api/v1/posts/{POST_ID}/like", token=B_TOKEN), 404)

print("== follows")
expect("follow without login -> 401", call("POST", f"/api/v1/users/{A_NAME}/follow"), 401)
expect("bob follows alice", call("POST", f"/api/v1/users/{A_NAME}/follow", token=B_TOKEN), 200)
expect("follow twice -> 409", call("POST", f"/api/v1/users/{A_NAME}/follow", token=B_TOKEN), 409)
expect("follow yourself -> 400", call("POST", f"/api/v1/users/{B_NAME}/follow", token=B_TOKEN), 400)
expect("follow unknown -> 404", call("POST", "/api/v1/users/nobody_" + suffix + "/follow", token=B_TOKEN), 404)
fl = expect("alice's followers", call("GET", f"/api/v1/users/{A_NAME}/followers"), 200)
check("bob is a follower", fl and [u["username"] for u in fl] == [B_NAME])
fg = expect("bob's following", call("GET", f"/api/v1/users/{B_NAME}/following"), 200)
check("alice is followed", fg and [u["username"] for u in fg] == [A_NAME])
check("alice followers_count=1", call("GET", f"/api/v1/users/{A_NAME}")[1]["followers_count"] == 1)
check("bob following_count=1", call("GET", f"/api/v1/users/{B_NAME}")[1]["following_count"] == 1)
expect("unfollow", call("DELETE", f"/api/v1/users/{A_NAME}/follow", token=B_TOKEN), 200)
expect("unfollow twice -> 404", call("DELETE", f"/api/v1/users/{A_NAME}/follow", token=B_TOKEN), 404)
check("counts back to 0", call("GET", f"/api/v1/users/{A_NAME}")[1]["followers_count"] == 0
      and call("GET", f"/api/v1/users/{B_NAME}")[1]["following_count"] == 0)

print("== admin-only endpoints are closed to normal users")
expect("create role as user -> 403", call("POST", "/api/v1/roles", {"name": "hacker"}, B_TOKEN), 403)
expect("update role as user -> 403", call("PUT", "/api/v1/roles/1", {"can_post": False}, B_TOKEN), 403)
expect("delete role as user -> 403", call("DELETE", "/api/v1/roles/1", token=B_TOKEN), 403)
expect("assign role as user -> 403", call("PUT", f"/api/v1/users/{B_NAME}/role", {"role_id": 1}, B_TOKEN), 403)
expect("create role without login -> 401", call("POST", "/api/v1/roles", {"name": "hacker"}), 401)
roles = expect("list roles is public", call("GET", "/api/v1/roles"), 200)
check("default 'user' role exists", roles and any(r["name"] == "user" for r in roles))
expect("get role", call("GET", f"/api/v1/roles/{roles[0]['id']}"), 200)
expect("unknown role -> 404", call("GET", "/api/v1/roles/999999"), 404)
check("bob cannot delete alice's post", call("DELETE", f"/api/v1/posts/{POST_ID}", token=B_TOKEN)[0] == 403)

if args.admin_email:
    print("== roles actually change what users can do (admin)")
    st, adm = call("POST", "/api/v1/auth/login", {"email": args.admin_email, "password": args.admin_password})
    check("admin login", st == 200, adm)
    ADM = adm["access_token"]
    user_role = next(r for r in roles if r["name"] == "user")

    def mk_role(name, **kw):
        return call("POST", "/api/v1/roles", {"name": f"{name}_{suffix}", **kw}, ADM)

    lim = expect("create role", mk_role("limited", can_post=False, description="no posting"), 201)
    expect("duplicate role name -> 400", mk_role("limited"), 400)
    expect("negative limit -> 422", mk_role("neg", max_followers=-1), 422)
    expect("assign role to bob", call("PUT", f"/api/v1/users/{B_NAME}/role", {"role_id": lim["id"]}, ADM), 200)
    check("bob's profile shows the new role", call("GET", "/api/v1/users/me", token=B_TOKEN)[1]["role"] == lim["name"])
    expect("bob cannot post (can_post=false) -> 403",
           call("POST", "/api/v1/posts", {"content": "nope"}, B_TOKEN), 403)
    expect("bob can still like", call("POST", f"/api/v1/posts/{POST_ID}/like", token=B_TOKEN), 200)
    expect("delete role in use -> 400", call("DELETE", f"/api/v1/roles/{lim['id']}", token=ADM), 400)

    upd = expect("update role: can post, max 1/day",
                 call("PUT", f"/api/v1/roles/{lim['id']}", {"can_post": True, "max_posts_per_day": 1}, ADM), 200)
    check("untouched fields were kept", upd and upd["description"] == "no posting")
    expect("bob's 1st post works", call("POST", "/api/v1/posts", {"content": "one"}, B_TOKEN), 201)
    expect("bob's 2nd post -> 429 (daily limit)", call("POST", "/api/v1/posts", {"content": "two"}, B_TOKEN), 429)

    nolike = expect("role without can_like", mk_role("nolike", can_like=False), 201)
    call("PUT", f"/api/v1/users/{B_NAME}/role", {"role_id": nolike["id"]}, ADM)
    expect("bob cannot like (can_like=false) -> 403",
           call("POST", f"/api/v1/posts/{POST_ID}/like", token=B_TOKEN), 403)

    nofol = expect("role with max_followers=0", mk_role("nofollowers", max_followers=0), 201)
    call("PUT", f"/api/v1/users/{C_NAME}/role", {"role_id": nofol["id"]}, ADM)
    expect("cannot follow someone at their follower limit -> 403",
           call("POST", f"/api/v1/users/{C_NAME}/follow", token=B_TOKEN), 403)

    mod = expect("moderator role", mk_role("mod", can_delete_any_posts=True), 201)
    call("PUT", f"/api/v1/users/{C_NAME}/role", {"role_id": mod["id"]}, ADM)
    expect("moderator deletes someone else's post",
           call("DELETE", f"/api/v1/posts/{POST_ID}", token=C_TOKEN), 200)
    check("alice's posts_count dropped to 0", call("GET", "/api/v1/users/me", token=A_TOKEN)[1]["posts_count"] == 0)

    nodel = expect("role without can_delete_own_posts", mk_role("nodelete", can_delete_own_posts=False), 201)
    p2 = expect("alice posts again", call("POST", "/api/v1/posts", {"content": "second"}, A_TOKEN), 201)
    call("PUT", f"/api/v1/users/{A_NAME}/role", {"role_id": nodel["id"]}, ADM)
    expect("alice cannot delete her own post (can_delete_own_posts=false) -> 403",
           call("DELETE", f"/api/v1/posts/{p2['id']}", token=A_TOKEN), 403)
    expect("an admin can delete it", call("DELETE", f"/api/v1/posts/{p2['id']}", token=ADM), 200)

    expect("assign unknown role -> 404", call("PUT", f"/api/v1/users/{B_NAME}/role", {"role_id": 999999}, ADM), 404)
    expect("assign role to unknown user -> 404",
           call("PUT", "/api/v1/users/nobody_" + suffix + "/role", {"role_id": user_role["id"]}, ADM), 404)
    expect("default role cannot be deleted -> 400", call("DELETE", f"/api/v1/roles/{user_role['id']}", token=ADM), 400)

    for name in (B_NAME, C_NAME, A_NAME):
        call("PUT", f"/api/v1/users/{name}/role", {"role_id": user_role["id"]}, ADM)
    for r in (lim, nolike, nofol, mod, nodel):
        expect(f"delete role {r['name']}", call("DELETE", f"/api/v1/roles/{r['id']}", token=ADM), 200)
else:
    print("== (skipped role/permission checks: pass --admin-email / --admin-password to run them)")

print("== deactivate account")
call("POST", "/api/v1/posts", {"content": "carol was here"}, C_TOKEN)
expect("carol deactivates", call("DELETE", "/api/v1/users/me", token=C_TOKEN), 200)
expect("deactivated user cannot log in -> 403",
       call("POST", "/api/v1/auth/login", {"email": f"carol_{suffix}@example.com", "password": PW}), 403)
expect("old token stops working -> 403", call("GET", "/api/v1/users/me", token=C_TOKEN), 403)
found = call("GET", f"/api/v1/users/search?q=carol_{suffix}")[1]
check("not in search", found == [])
expect("cannot be followed -> 404", call("POST", f"/api/v1/users/{C_NAME}/follow", token=B_TOKEN), 404)
lst = call("GET", "/api/v1/posts?limit=100")[1]
check("her posts are hidden", all(p["author_username"] != C_NAME for p in lst))

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
