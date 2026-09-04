# Changesets

Every user-visible change to `xrpl-message-verify` is accompanied by a changeset: run
`pnpm changeset`, pick the bump (`patch` for fixes, `minor` for new options or Reason codes,
`major` when an existing input starts returning something different) and describe the change for
the CHANGELOG. Changesets accumulate on `main` and are folded into a version PR; merging that PR
bumps the version and the changelog, and a maintainer then pushes a `v*` tag, which triggers
`release.yml` to publish through npm trusted publishing. The `web` package is ignored here because
it is deployed to GitHub Pages, not published to npm.
