# GitHub publication and maintenance

Publish reviewed code, synthetic tests and documentation only. Start with a private repository for this security workflow unless the owner explicitly approves public distribution. Never upload the entire workstation folder, raw reports, generated packages, populated configuration, operational exports or credential files.

## Publication checklist

1. Confirm the destination owner/repository and visibility. Do not infer an organization or publish publicly by default.
2. Confirm that blank environment/deployment examples have no values and that populated files remain under `config/local/`.
3. Run tests, lint/format, infrastructure lint and repository preflight. Inspect the complete staged diff and file list.
4. Run an approved full-history secret scanner before pushing existing history. The built-in preflight scans the current tracked/index content only.
5. For an existing repository, read its default branch and conventions and publish on a reviewed branch/PR without overwriting unrelated files or force-pushing.
6. Verify the remote commit, CI results and repository visibility after publishing. An API commit receipt alone does not verify every uploaded file or CI result.

```bash
python3.12 -m unittest discover -s tests -q
ruff check .
ruff format --check .
cfn-lint template.yaml
python3.12 scripts/check_repository.py --staged
git diff --cached --stat
git diff --cached --check
```

If the directory is not yet a Git repository, initialize a dedicated repository for this application, not its parent containing unrelated work. Add only the reviewed application/documentation paths. Configure the intended commit identity locally; do not change global Git settings as part of publication.

For a newly approved private destination, GitHub CLI can create and push the local repository after the owner/name is supplied:

```bash
gh repo create <owner>/<approved-name> --private --source . --remote origin --push
```

This is an example, not an instruction to create an arbitrary repository. For an existing nonempty destination, use its established review workflow instead of pushing a disconnected initial commit to its default branch.

Removing configuration from the working tree does not remove earlier commits. For a first publication from unpublished local history, retain the original branch locally and prepare a reviewed root snapshot containing only sanitized files. Push only that approved publication branch, not all branches, tags or a repository mirror. Do not rewrite an already-published repository without its owner's approved incident and coordination process.

## Repository protection

Require pull requests and successful validation on the protected default branch. Choose actual code owners for the security and infrastructure paths. Enable private vulnerability reporting, available secret scanning and push protection, and Dependabot. Do not imply those remote settings are enabled merely because this guide exists.

The included CI uses pinned action commits, read-only repository permissions and no deployment credentials. It validates publication boundaries, tests, lint/format, infrastructure, dependency advisories, offline preview and release packaging. It does not deploy AWS or create Jira issues. Fork PRs must not receive production credentials or execute a deployment workflow with write authority.

Dependabot proposes runtime/development dependency and action updates. Hash-locked runtime requirements still need reviewed replacement wheel hashes; do not remove hash enforcement to make an update pass. Test the application and rebuild the manifest after a dependency change. [GitHub dependency update configuration](https://docs.github.com/en/code-security/dependabot/working-with-dependabot/dependabot-options-reference)

## Release and rollback

Record the reviewed Git commit, archive SHA-256, runtime lock hash, template hash, approved private configuration revision and staging results. Keep the generated zip outside Git; distribute it through an approved release pipeline or access-controlled artifact store.

Changes to environment values, source profiles or policies are operational changes even when code is unchanged. Review them separately. A rollback restores code/configuration compatibility; it cannot undo Jira issues already created. Inspect existing checkpoints and signed mappings rather than erasing DynamoDB or replaying uncertain writes.

## If sensitive content was committed

Stop publication and revoke/rotate exposed credentials first. Identify affected history, branches, artifacts, caches and recipients. Follow the organization's incident procedure and approved history-rewrite process; do not force-push a rewrite without coordinating with repository owners and collaborators. Removing the latest file does not erase prior commits or copies. [GitHub removal guidance](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
