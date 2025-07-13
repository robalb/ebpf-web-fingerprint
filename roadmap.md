
# Roadmap

## backlog

- Automatic TLS management
- env variable configuration
- Containerized builds
- Define a public interface:

        ListenAndServe()
        Lookup(r *http.Request) (Handshake)
        //probes
        http.Server.ConnContext
        tls.Config.GetConfigForClient

