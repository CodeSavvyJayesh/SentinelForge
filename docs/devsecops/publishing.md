# Publishing the VS Code extension

The extension is ready to publish: it has a licence, an icon, a package that
carries the scanner, and a one-time setup that installs the scanner's packages
on the user's machine. What is left needs your own accounts, so it is written
down here rather than done.

## 1. Build the package

```powershell
cd C:\SentinelForge\vscode-extension
node scripts\package.js
```

This writes `sentinelforge-0.2.0.vsix` (about 400 KB). Try it before publishing,
on a machine — or a Windows user account — that has never had SentinelForge:

```powershell
code --install-extension sentinelforge-0.2.0.vsix
```

Open any folder, run **SentinelForge: Scan workspace**, accept the one-time
setup, and check that findings appear and that a quick fix applies. Uninstall it
afterwards from the Extensions view.

## 2. Create a publisher (once)

1. Go to <https://marketplace.visualstudio.com/manage> and sign in with a
   Microsoft account.
2. Create a publisher. Its **ID must be `CodeSavvyJayesh`**, because that is the
   `publisher` in `vscode-extension/package.json`. If you choose another ID,
   change `package.json` to match and build the package again.

## 3. Upload the package

On the same page: **New extension → Visual Studio Code**, and upload
`sentinelforge-0.2.0.vsix`. The Marketplace checks it and publishes it, usually
within minutes. After that, anyone can search **SentinelForge** in VS Code's
Extensions view and click Install.

(The command-line way does the same: `npx @vscode/vsce login CodeSavvyJayesh`
with a personal access token from Azure DevOps with the *Marketplace (Manage)*
scope, then `npx @vscode/vsce publish --packagePath sentinelforge-0.2.0.vsix`.)

## 4. Optional: Open VSX

Editors built on VS Code that do not use Microsoft's Marketplace (VSCodium,
Gitpod) install from <https://open-vsx.org>. Sign in there with GitHub, create
the `CodeSavvyJayesh` namespace, and upload the same `.vsix`.

## Publishing a new version

Raise `version` in `vscode-extension/package.json` (0.2.0 → 0.2.1), build the
package again, and upload it. A version can be published only once.

## What users need

- VS Code 1.80 or newer.
- Python 3.12 or newer, on the PATH (on Windows, the `py` launcher is found too).
- Internet access once, for the one-time setup.
- For fixes from the local model only: Ollama, with `qwen2.5-coder:7b` pulled.
  Built-in fixes and scanning need no model.
