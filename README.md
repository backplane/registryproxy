# RegistryProxy

RegistryProxy is a reverse proxy designed for Docker registries. It provides URL rewriting capabilities, allowing users to set up a custom domain and namespace that serves data from another registry, be it private or public. This enables more accessible namespacing and domain handling for Docker images stored in various registries.

Repo       | URL
---------: | --------------------------------------------------
GitHub     | <https://github.com/backplane/registryproxy>
Docker Hub | <https://hub.docker.com/r/backplane/registryproxy>

## Features

- **Custom Domain Mapping**: Map any domain to a target Docker registry with configurable paths.
- **Private to Public Proxying**: Expose private repositories on public URLs securely.
- **Capability URL Support**: Utilize capability URLs for enhanced security and privacy.

## Example Configuration

Below is an example configuration that demonstrates setting up RegistryProxy:

```yaml
# Generate "secretkey" with: openssl rand -hex 32
# Generate "auth" with: echo "Basic $(printf '%s:%s' 'myusername' 'mypassword' | base64)"
listen_addr: 0.0.0.0
port: 5000
secretkey: 796280902778385984e2acd2868447a0ee703a8fab0ed7e69103cd50b9e3cddd
proxies:
  "bp/":
    registry: index.docker.io
    remote: backplane
  "0ebb01be-0a22-4639-898c-bc8c2d20942d/nginx":
    registry: ghcr.io
    remote: modem7/docker-rickroll
    auth: "Basic cmljazpOZXZlckdvbm5hTGV0WW91RG93bjI="
```

With the above configuration, navigating to reg.example.com/bp/true will serve the image from hub.docker.com/r/backplane/true. It also supports proxying a private repository at ghcr.io to a public URL.

To use RegistryProxy, follow these steps:

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/registryproxy.git
    ```
2. Create a config.yaml file with your specific configurations.
3. Build and run the proxy:
    ```bash
    docker build -t registryproxy .
    docker run -p 5000:5000 registryproxy
    ```

## Security Considerations

* Token Handling: In an effort to prevent end users from abusing the temporary tokens that are issued by upstream registries, RegistryProxy uses encrypted PASETO tokens to securely encapsulate JWTs received from registries.

* When deploying:
    * Deploy behind a TLS-terminating load balancer to ensure encrypted client connections.
    * Enable abuse detection, rate limiting, and bandwidth circuit breaker features in the load balancer infrastructure.

## Project Status

This project is currently in development and should not currently be used in production environments.

## Credits

### Forked From `ahmetb/serverless-registry-proxy`

This project is forked (on 2-May-2024) from [Ahmet Alp Balkan's Serverless Container Registry Proxy](https://github.com/ahmetb/serverless-registry-proxy) which is an excellent open source (Apache licensed) project that did all the heavy lifting of figuring out how to proxy a registry. Thanks Ahmet.

Post-fork modifications are by Backplane BV (a Belgian IT consultancy).

## License

Distributed under the Apache License 2.0. See LICENSE.txt for more information.
