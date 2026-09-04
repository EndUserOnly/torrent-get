# Release controls

These controls are mandatory for production publication.

1. The public release must be byte-for-byte identical to the tested installed/local candidate.
2. Every release artifact must be listed in a SHA-256 manifest.
3. The manifest and release artifacts must have verifiable cryptographic signatures.
4. Installers must verify the packaged payload before installing it.
5. Production releases must be made from a cryptographically signed, immutable tag.
6. The `production` branch must reject force-pushes and deletion.
7. Publication credentials must have the minimum permissions necessary.
8. The release must be reconstructable from the source tree at the signed tag.
9. An offline release copy must be written only after OneDrive is confirmed mounted.

No production publication may proceed past a failed gate.
