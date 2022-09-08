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


## Installation with Traefik

You need to have traefik forward the Path `/` to this application.

I only use docker swarm. You'd do something like the following:

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

## Note

For some reason that I haven't bothered looking into,
I have to first load `/` in the browser.
I think it has something to do with cookies going through traefik simpleauth,
and I could probably fix it with some JavaScript,
but this is good enough for me.
