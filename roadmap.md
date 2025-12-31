
# Roadmap

## backlog

- [x] Automatic TLS management
- [x] env variable configuration
- [ ] Containerized builds
- [ ] Define a public interface:

        ListenAndServe()
        Lookup(r *http.Request) (Handshake)
        //probes
        http.Server.ConnContext
        tls.Config.GetConfigForClient

