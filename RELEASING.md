# Releasing Klaxond

Klaxond has two deliberately separate release surfaces:

- the private maintainer release in Gitea, which publishes a private amd64 image
  and can roll that image out to the homelab;
- the public GitHub/GHCR release, which remains fail-closed until publication is
  explicitly enabled and all public-platform gates have evidence.

A version tag must never rebuild different source under the same version or be
moved after publication.

## Private maintainer release

Before pushing `vX.Y.Z` to the private Gitea repository:

1. synchronize the version sources listed below;
2. pass the complete Gitea `check` job on the exact `main` commit, including
   PostgreSQL, SDK, OpenAPI and Chromium/Firefox/WebKit coverage;
3. run `bash scripts/test-clean-install.sh` locally;
4. verify the downstream Ansible change, database/config backup checks,
   migration gate, postflight and rollback path;
5. confirm the repository and package visibility remain private.

The Gitea tag workflow promotes the tested immutable commit image to `X.Y.Z`
and `X.Y`, then invokes the version-pinned Semaphore deployment. It must not
enable or invoke the GitHub publication path. After deployment, verify the live
version, health, restart count, schema, policy snapshot integrity, ownership,
metrics and exact rollback artifacts, then complete the documented soak.

## Public release

Numbered GitHub releases promote an already-tested immutable commit. They are a
separate operation from a private Gitea tag and the maintainer rollout.

### Before tagging

1. Update `Cargo.toml`, the root lockfile, `docs/openapi.yaml`, Compose image
   defaults, `.env.example` and `CHANGELOG.md` to the same version.
2. Run the checks in `CONTRIBUTING.md`, including the Chromium, Firefox and
   WebKit passkey lifecycle.
3. Run `bash scripts/test-clean-install.sh` against the candidate backend image.
4. Complete the physical Safari/macOS and iPhone/iPad smoke tests in
   `docs/browser-support.md`.
5. Confirm the intended GitHub repository and GHCR visibility, private
   vulnerability reporting, and that no unresolved high-severity dependency or
   secret-scanning finding remains.
6. Only when publication is explicitly authorized, set the GitHub Actions
   repository variable `KLAXOND_PUBLICATION_ENABLED=true`. It is absent by
   default, so ordinary pushes can validate the repository without publishing
   images or releases.
7. Push the candidate commit to `main` and wait for the GitHub workflow to
   publish and verify both architecture manifests for that exact SHA.

### Tag and publish

Create `vX.Y.Z` only on the verified `main` commit. The tag workflow must:

1. rerun source and browser validation;
2. locate the existing `sha-<commit>` backend and frontend manifests;
3. promote those exact digests to `X.Y.Z`, `X.Y` and `latest` without a rebuild;
4. publish the self-verifying Compose bundle and generated release notes.

Do not move or reuse a published version tag.

### Verify the public release

From a clean, unauthenticated environment:

1. download the release bundle;
2. extract it and run `sha256sum --check SHA256SUMS`;
3. run `docker compose config --quiet`;
4. pull both numbered images anonymously and inspect the amd64/arm64 manifest;
5. start the backend with a new volume, require `/healthz` and
   `klaxond doctor --offline`, then verify disabled ingress rejects requests;
6. confirm the GitHub release, package tags and repository version all agree.

The maintainer deployment is a separate downstream rollout. Its success does
not replace the clean public-install verification above.
