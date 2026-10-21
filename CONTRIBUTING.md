# How to contribute

We'd love for you to contribute and welcome your help. Here are some guidelines to follow:

- [Issues and Bugs](#issue)
- [Submitting a fix](#submitting)
- [Feature Requests](#features)
- [Questions](#questions)

## <a name="issue"></a> Did you find a issue?

* **Ensure the bug was not already reported** by searching on GitHub under *Issues*

* If you're unable to find an open issue addressing the problem, open a new one

## <a name="submitting"></a> Did you write a patch that fixes a bug?

Open a new GitHub pull request with the patch following the steps outlined below. Ensure the PR description clearly describes the problem and solution. Include the relevant issue number if applicable.

Before you submit your pull request consider the following guidelines:

* Search *Pull Requests* for an open or closed Pull Request
  that relates to your submission. You don't want to duplicate effort.

### Submitting a Pull Request

Please follow these steps for all pull requests. These steps are derived from the [GitHub flow](https://docs.github.com/en/get-started/using-github/github-flow).

#### Step 1: Fork

Fork [SolaceLabs/wireshark-smf-plugin](https://github.com/SolaceLabs/wireshark-smf-plugin) and clone your fork locally:

```sh
git clone https://github.com/<your-username>/wireshark-smf-plugin
cd wireshark-smf-plugin
git remote add upstream https://github.com/SolaceLabs/wireshark-smf-plugin
```

#### Step 2: Branch

Make your changes on a new git branch in your fork of the repository:

```sh
git checkout -b my-fix-branch main
```

#### Step 3: Commit

Commit your changes:

```sh
git commit -a -m "Your commit message"
```

Individual commit messages don't need to follow any particular format, since they are squashed on merge.

Note: the optional `-a` option stages modified and deleted files that git already tracks. New files must be added with `git add` first.

#### Step 4: Stay up to date

Pull requests are squash-merged, so your branch history doesn't need to be tidy. To pick up changes from `main`, either rebase or merge. Rebasing is preferred since it keeps the PR diff cleaner:

```sh
git fetch upstream
git rebase upstream/main
```

If you have already pushed your branch, rebasing rewrites its history, so your next push needs `git push --force-with-lease origin my-fix-branch`.

#### Step 5: Push

Push your branch to your fork in GitHub:

```sh
git push origin my-fix-branch
```

#### Step 6: Pull Request

In GitHub, open a pull request against `SolaceLabs/wireshark-smf-plugin:main`. Since the PR is squash-merged, its title becomes the commit message on `main` and must follow [Conventional Commits](https://www.conventionalcommits.org) (e.g. `fix: ...`, `feat: ...`, `docs: ...`, `ci: ...`).

When fixing an existing issue, use the [closing keywords](https://docs.github.com/en/issues/tracking-your-work-with-issues/using-issues/linking-a-pull-request-to-an-issue) in the PR description to close the associated GitHub issue.

* If we suggest changes then:
  * Make the required updates.
  * Commit these changes to your branch (ex: my-fix-branch).
  * Push your branch again. The pull request updates automatically.

That's it! Thank you for your contribution!

## <a name="features"></a> **Do you have an ideas for a new feature or a change to an existing one?**

* Open a GitHub issue and label it as an *enhancement* and describe the new functionality.

##  <a name="questions"></a> Do you have questions about the source code?

* Ask any question about the code or how to use Solace technologies in the [Solace community](https://community.solace.com).
