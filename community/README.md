# The working group's kit

This folder holds what the ECL-1 Working Group uses in the public repository
of ECL-1:

- [`WORKING_GROUP.md`](WORKING_GROUP.md): how to join, the working sessions
  and their notes, and the contact address.
- [`DISCUSSIONS.md`](DISCUSSIONS.md): the categories of the repository's
  discussions.
- [`implementers.yaml`](implementers.yaml) and
  [`implementers.schema.json`](implementers.schema.json): the implementers
  registry, empty at Version 1.0, and its schema
  ([CONFORMANCE_CLAIMS](../governance/CONFORMANCE_CLAIMS.md)).
- [`settings.yaml`](settings.yaml): the settings that the maintainer fills in
  before the repository is published: the GitHub repository, the editors'
  team, the contact addresses and the schedule of the working sessions. Other
  files refer to these values by name, except the files it lists under
  `contact_address_files`, which carry the contact address in place.
- `github/`: the files that the public repository keeps in its `.github/`
  folder, where GitHub reads them: the issue forms (`ISSUE_TEMPLATE/`), the
  pull request template and `CODEOWNERS`. `github/` is their one source: the
  maintainer fills in the editors' team in `github/CODEOWNERS` with the other
  settings before the release is built, and `.github/` is a copy of `github/`
  made when the repository is staged.

The issue forms are:

| Form | Label | Use |
|---|---|---|
| ECL-1 Working Group sign-up | `working-group` | Sign up as a participant |
| Public review comment | `public-review` | Comment on a version in its public review window |
| Propose a change | `proposal` | Raise a problem or propose a change to ECL-1 |
| Report an erratum | `erratum` | Report an error in a published version |
| Appeal a decision | `appeal` | Take an appeal to a public issue after the chair's answer |
