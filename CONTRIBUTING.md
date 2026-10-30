# Contributing to credentials-support

This document describes the rules for commit messages in this repository.

## Commit messages

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/), as described in the [Conventional Commits Cheatsheet](https://gist.github.com/qoomon/5dfcdf8eec66a051ecd85625518cfd13). The rules below are based on the cheat sheet, with one difference: scopes are not used in this project.

### Format

```
<type>: <description>

[optional body]

[optional footer]
```

For a breaking change, add `!` directly after the type:

```
<type>!: <description>
```

The first line is required. The body and the footer are optional, and each is separated from the previous part by an empty line.

### Types

| Type | Use for |
|---|---|
| `feat` | Commits that add, adjust or remove a feature of the API. |
| `fix` | Commits that fix a bug in the API. |
| `refactor` | Commits that rewrite or restructure code without changing the behaviour of the API. |
| `perf` | Commits that improve performance. This is a special type of `refactor`. |
| `style` | Commits that only change code style (white space, formatting and so on) and do not affect behaviour. |
| `test` | Commits that add missing tests or correct existing tests. |
| `docs` | Commits that only affect documentation, such as `README.md`, `docs/` and Javadoc. |
| `build` | Commits that affect the build, such as Maven configuration, dependencies and the project version. |
| `ops` | Commits that affect operational components, such as GitHub Actions workflows, Dependabot and deployment scripts. |
| `chore` | Other tasks, such as the initial commit or changes to `.gitignore`. |

There are no other types. For example, `ci` is not used, use `ops` instead. A version bump is `build`, not `chore`.

### Description

- Use the imperative, present tense: "add", not "added" or "adds". A good test is that the description completes the sentence "If applied, this commit will ...".
- Do not capitalize the first letter. Acronyms, such as `JWK` or `PKCS#11`, may start the description.
- Do not end the description with a period.

### Body

- Explain the reason for the change, and how the new behaviour differs from the old.
- Use the imperative, present tense, just like in the description.

### Footer

- The footer holds information about breaking changes and references to issues, for example `Closes #123`.
- A breaking change that is not obvious from the description is described in a footer that starts with `BREAKING CHANGE:`. A message with such a footer must also mark the type with `!`.

### Breaking changes and versions

- A commit marked with `!` leads to a new major version.
- A `feat` commit leads to a new minor version.
- All other commits lead to a new patch version.

### Merge and revert commits

Use the default messages that Git creates for merge commits (`Merge ...`) and revert commits (`Revert "..."`).

### Examples

```
feat: add support for loading credentials from PKCS#12 files
```

```
fix: close key store input stream after loading
```

```
refactor!: remove deprecated code

BREAKING CHANGE: The deprecated set...Function methods of JwkTransformerFunction are removed. Use the
corresponding with...Function methods instead.
```

```
build: bump version to 2.3.0-SNAPSHOT
```

```
build: upgrade Spring Boot to 4.1.2
```

```
ops: add workflow for publishing to Maven Central
```

```
docs: describe credential monitoring in README
```

```
chore: ignore IDE files
```

