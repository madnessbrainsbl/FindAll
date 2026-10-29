# Security

Keep API keys in `jobfind/osint-keys.env` or environment variables. The committed
example has empty values. Personal profiles, databases, output folders, network
state and downloaded executables are excluded from publication.

Before publishing, scan the clean export with Gitleaks and inspect its file list.
Secret scanning cannot establish that a document is free of personal information.
Never upload a populated working directory as an archive.

Personal/contact email addresses of the owner must not appear in publication
files, commit messages, co-author trailers or author/committer/tagger metadata.
Check the exact staged files and every outgoing commit before each upload. Use
the authenticated GitHub account's verified noreply address for Git identities
and `example.invalid` for contact examples. Keep upstream attribution notices.

Do not include credentials, personal research data or raw provider responses in
public issues. Use GitHub private vulnerability reporting when enabled, or arrange
private contact with the repository owner.

If a credential is published, revoke or rotate it immediately. Removing a file
in a later commit does not remove it from Git history.
