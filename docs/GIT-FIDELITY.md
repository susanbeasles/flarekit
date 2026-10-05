# Git capture fidelity

| Material | Capture | Automatic fresh restore |
| --- | --- | --- |
| Refs and packed refs | Bytes plus named-ref/SHA inventory | Reinstalled; exact inventory compared |
| Reflogs | Primary/common logs and linked admin records | Primary/common logs reinstalled; no global activity/identity claim |
| Objects | All locally available primary objects, including dangling and materialized local alternates | All-object inventory equality plus fsck |
| Index/staged changes | Selected Git directory's index; linked worktree index records | Selected index reinstalled; staged/unstaged bytes retain distinct states |
| Working tree | Selected tree, including ignored/untracked files | Regular files restored; symlink targets retained separately |
| Linked worktrees | Working directory bytes, original path mapping and administrative records | Kept in capture; automatic linked-worktree reconstruction not implemented |
| Local configuration | Common config/config.worktree retained in quarantine | Never installed automatically |
| Global/included configuration | Not captured | Never activated |
| Hooks | Common hooks retained in quarantine | Never installed/executed automatically |
| Primary alternates | Recursively materialized into self-contained primary object store | External alternate pointers omitted |
| LFS | Locally present object files | Kept in capture; full pointer-to-object coverage and automatic reinstall pending |
| Submodules | Local `.git/modules` stores and working-tree bytes | Kept in capture; nested alternate resolution and recursive reconstruction pending |
| Ownership/ACL/xattrs/resource forks/file modes/empty directories | Not guaranteed in this increment | No macOS-fidelity claim |
| Shallow history | Shallow boundary recorded | Existing local history only; missing remote ancestry is not invented |

The capture reports these coverage fields. It is not labeled a complete external-history backup. The tests demonstrate dangling-object recovery, refs, index preservation, source index unchanged, hook quarantine and content-tamper rejection. Linked worktree/LFS/submodule edge cases require additional acceptance tests before production qualification.

Source Git commands disable optional locks, fsmonitor, hooks, system/global configuration and prompting. Source-local configuration is read for Git interpretation; this is not a sandbox for arbitrary hostile repositories. Capture checks ref stability and file size/mtime changes but cannot guarantee one atomic moment across an active repository. Quiesce repositories for strict capture until a reviewed snapshot adapter exists.
