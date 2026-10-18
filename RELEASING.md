# Releasing

Releases are created by pushing a tag. The `Create Release` workflow then builds the plugin for all platforms and creates a draft release with the archives and installation instructions.

1. Make sure the commit to release is pushed and `WIRESHARK_TARGET_VERSION` in `cmake/WiresharkVersion.cmake` is the Wireshark version to release for.

2. List the existing tags for that Wireshark version to find the next patch version
```sh
git fetch --tags
git tag -l "v$(cmake -P cmake/WiresharkVersion.cmake 2>&1 | cut -d. -f1,2).*"
```

3. Tag the commit and push the tag
```sh
git tag vMAJOR.MINOR.PATCH
git push origin vMAJOR.MINOR.PATCH
```

4. Once the workflow finishes, review the draft on the releases page and publish it.

The tag must be `vMAJOR.MINOR.PATCH`, where `MAJOR.MINOR` matches `WIRESHARK_TARGET_VERSION` and `PATCH` is the SMF plugin patch version. Otherwise the workflow fails before building anything.

> [!IMPORTANT]
> Create releases by pushing a tag, not from the GitHub releases page. Publishing a release there creates the tag and triggers the workflow, which then fails because published releases are never modified.

If the tag was wrong and no release was published, delete the draft release (if any) and the tag, then start over
```sh
git tag -d vMAJOR.MINOR.PATCH
git push origin :refs/tags/vMAJOR.MINOR.PATCH
```
