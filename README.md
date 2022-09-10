# Simple Auth

All this does is present a login page.
Upon successful login, the browser gets a cookie,
and further attempts to access will get the success page.

I made this to use with the Traefik forward-auth middleware.
I now use Caddy: it works with that too.
All I need is a simple password, that's easy to fill with a password manager.
This checks those boxes.

## Format of the `passwd` file

It's just like `/etc/shadow`.

    username:crypted-password

We use sha256,
until there's a Go library that supports everything.

There's a program included called `crypt` that will output lines for this file.


## Installation with Caddy

Run simpleauth as a service.
Make sure it can read your `passwd` file,
which you set up in the previous section.

You'll want a section like this in your Caddyfile:

```
forward_auth simpleauth:8080 {
  uri /
  copy_headers X-Simpleauth-Token
}
```

## Installation with Traefik

I don't use Traefik any longer, but when I did,
I had it set up like this:

```yaml
services:
  my-cool-service:
    # All your cool stuff here
    deploy:
      labels:
        # Keep all your existing traefik stuff
        traefik.http.routers.dashboard.middlewares: forward-auth
        traefik.http.middlewares.forward-auth.forwardauth.address: http://simpleauth:8080/
  simpleauth:
    image: ghcr.io/nealey/simpleauth
    secrets:
      - password
    deploy:
      labels:
        traefik.enable: "true"
        traefik.http.routers.simpleauth.rules: "PathPrefix(`/`)"
        traefik.http.services.simpleauth.loadbalancer.server.port: "8080"

secrets:
  password:
    file: password
    name: password-v1
```

# How It Works

Simpleauth uses a token cookie, in addition to HTTP Basic authentication.
The token is an HMAC digest of an expiration timestamp,
plus the timestamp.
When the HMAC is good, and the timestamp is in the future,
the token is a valid authentication.
This technique means there is no persistent server storage,
but also means that if the server restarts,
everybody has to log in again.

Some things,
like WebDAV,
will only ever use HTTP Basic auth.
That's okay:
Simpleauth will issue a new token for every request,
and the client will ignore it.
