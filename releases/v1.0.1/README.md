# torrent-get 1.0.1

Recovery and queue ownership update, 2026-10-29. The packaged commands match
the installed Pop!_OS candidate byte for byte. Native worker and dependencies
are unchanged from v1.0.

- Keep queue ownership when worker shutdown fails.
- Archive job identity, resume data, and approvals before removal.
- Retain payload and logs by default; exclude paused jobs from bulk pruning.
- Add `prune --dry-run` and a compatibility queue entry point.
- Reconcile stale global pause job IDs and retain unfinished resume work.
- Handle invalid payload paths during reconciliation.

Run `./verify.sh` before installation and `./install.sh` as the desktop user.
See ../v1.0/README.md for platform prerequisites and service activation.

Run regression tests from the repository root:

```sh
python3 -m unittest discover -s releases/v1.0.1/tests -v
```

The tests use temporary state and mocked worker control. They do not operate
on the live torrent queue. No concurrency caps were added.
