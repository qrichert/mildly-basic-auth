# mildly-basic-auth

![Crates.io License](https://img.shields.io/crates/l/mildly-basic-auth)
![GitHub Tag](https://img.shields.io/github/v/tag/qrichert/mildly-basic-auth?sort=semver&filter=*.*.*&label=release)
[![crates.io](https://img.shields.io/crates/d/mildly-basic-auth?logo=rust&logoColor=white&color=orange)](https://crates.io/crates/mildly-basic-auth)
[![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/qrichert/mildly-basic-auth/ci.yml?label=tests)](https://github.com/qrichert/mildly-basic-auth/actions)

_Basic auth with nicer UX._

> A transparent reverse proxy that shows a password page, sets a secure
> session cookie, and otherwise gets out of the way.

DROP IN. this is designed around _simplicity_ for people who need quick
good-enough protection, no headache, no docs to read, nothing new to
learn this could have been named "very-lazy-auth" too.

designed to be as transparant and low footprint as possible both for DX
and UX.

idea: it shows a password field, if you enter the password correctly it
sets a cookie and acts as a full passthrough, something quite simple to
protect work-in-progress projects and or personal docs.

Basically:

```python
if not authenticated:
    redirect_to_password_gate()
else:
    passthrough_transparently()  # as if we're not even there...
```

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="demo/dark.png">
  <img alt="Rendered visual of the auth gate." src="demo/light.png">
</picture>

also double check nothing like that exists. i remember searching and
found nothing but was always lazey building it. best alternative was
oauth2 container (quayio or something ? don't remember), it's setup once
and forget but it's a real big pain to setup for something simple like
that (google auth etc.), i want a drop-in-and-it-works kinda solution.
basically basic-auth with a nicer user-experience, basic auth is painful
and never remembers you credentials

maybe a pun with basic-auth ? like mildly-basic-auth

looking into caddy forward auth. on paper looks simple -> if ok send ok,
if not send html page with password. but where does the logic go? now
you have to put the logic ? now you need another service for that( which
we would need too tho), it's a fair match i think, not a straight win
for caddy here, even tho native. do others work the exact same ?
nginx/trafik ? in which case it's a +, if caddy is idiosyncratic maybe
not. i personnally use caddy a lot for most anything, unless i go k3s in
which case i go traefik

looking into it nforwardauth does almost what i want but looks overly
complicated, so still quite torn my idea is much more lightweigh in but
usage and what it does. it's really just a very very transparent
password wall, a single html page (with css and svg icons embedded) that
is served or overridden for custome styling

designed to be used with docker. by default runs on `0.0.0.0:8000` with
a non root `10001` user. debian slim image.

```
/btw do you recommend alpine or debian here ?

    Debian slim — and it's not close for this project.

    The reasoning, specific to what we're building:

    - musl's allocator is a real problem for a proxy. Alpine means musl
    libc, and musl's default malloc degrades badly under multi-threaded
    allocation contention. A reverse proxy allocates per-request across a
    Tokio thread pool — exactly the workload that hits that cliff. You'd
    end up bolting on mimalloc/jemalloc to claw the performance back, which
    is complexity a "mildly basic" tool shouldn't carry.
    - We don't get Alpine's usual payoff. The stack is rustls (via
    axum-reverse-proxy's hyper-rustls) + blake3 — both pure Rust, no
    OpenSSL, no C deps. The classic "Alpine avoids the glibc/OpenSSL mess"
    win doesn't apply, so you'd take musl's downsides for little upside.
    - musl's DNS resolver is weaker. It historically mishandles some
    resolver behaviors (e.g. parallel A/AAAA, larger TCP responses). A
    proxy that resolves an upstream hostname is precisely where that
    occasionally bites. glibc just works.
    - glibc = the default target. No musl cross-compilation setup, no -musl
    toolchain in CI. Debian slim uses the stock x86_64-unknown-linux-gnu
    build you're already producing.
    - The README already commits to it (§58-59: "debian slim image"), so
    this is consistency, not a new decision.
```

published to Docker Hub as `qrichert/mildly-basic-auth`.

drop-in usage (this is v0, works today):

```yml
services:
  auth-gate:
    image: qrichert/mildly-basic-auth:latest
    ports:
      - "80:8000"
    environment:
      MBA_PASSWORD: "h3lloW0rld"
      MBA_UPSTREAM: http://app:2001
  app:
    image: traefik/whoami
    command:
      - "--port=2001"
```

use a long random `MBA_PASSWORD`, not something guessable like the
`h3lloW0rld` above — the session cookie is a fast digest of it, so a
leaked cookie is an offline verifier of the password.

v0 sets a non-`Secure` cookie, so over plain HTTP (like the `80:8000`
above) the password and session token are visible on the wire. for
public deployments put it behind Caddy/Traefik for TLS; direct HTTP is
fine only on a trusted network.

v1 idea:

- different auth methods:
  - plain password only (most convenient, actually enough for many use
    cases)
  - hashed password (`<algo>:<hash>`)
  - list of user/pass possible
  - bearer token (header-only check, maybe, not in v1 tho)
- support env vars, env file, yaml config file (set `MBA_CONFIG_FILE` or
  discovered).
- custom template (set `MBA_TEMPLATE_FILE` or discovered bind mount to
  `/etc/template.html`). loaded/rendered at startup. likely will need a
  template engine to interpolate variables and conditionally render
  fields based on auth method (username + password or password alone, in
  that case minijinja looks good).
- rate-limiting/host whitelist/etc. should probably be handled with a
  reverse proxy like Caddy etc. in front. not our job probably.
- of course the proxy part is not homemade, use a proper dependency
- settings:
  - auth method
  - host/port bind
  - log stuff or not
  - template
  - session lifetime
  - page:
    - lang
    - title
    - placeholder
    - etc., enabling translation without a custom template
- non goals:
  - ldap
  - oauth
  - admin panel
  - policy rules
  - redis
  - MFA/TOTP
  - sso
  - etc.

  look at password wall in ../hoplageiss the goal is to rip that one out
  of the project and replace it with this "middleware" container.
