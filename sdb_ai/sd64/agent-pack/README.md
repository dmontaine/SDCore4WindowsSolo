# agent-pack: what an AI agent needs to work in SD Core Solo for Windows

S.69 rows 1 and 1b of the AI plan, carried to SD Core Solo for Linux (LSOLO 55, 20 Oct 2026) and from there to SD Core Solo for Windows (15 Nov 2026, RELEASE_1.1 253). Documents, a generator and a free check. **Nothing here is installed, compiled into SD or shipped by the installer**, as in SD Core Solo for Linux (SD Core for Windows installs its guide and pack as text; the Solo products do not), and nothing here calls a model, holds a key, opens a wall or changes ssh.

| path | what | made by |
|---|---|---|
| `guide/sd-basic-guide.md` | the SD BASIC dialect guide: language, system, walls, 20+ worked programs | by hand; its blocks were compiled and run on SD Core Solo for Linux (`gplbld/sandbox-guide.py` there), whose BASIC this tree shares |
| `pack/` | the generated knowledge pack: one chunk per TCL verb, query keyword, VOC type, dictionary type and conversion, BASIC statement, function, `$mode`, option, message, setting and key group, with the source and line of each | `mkpack.py`, from THIS tree; guarded by `gplbld/test-pack-units.py` |
| `core-start.md` | the "start here" text embedded in the pack's core | by hand |
| `skill/sd-core-solo/` | a Claude Code skill: `SKILL.md` by hand, `references/` (the guide and the pack) generated | `mkpack.py --write` |
| `templates/` | a CLAUDE.md template for a project that lives in the SD account; an `.mcp.json` shape that does NOT work yet | by hand |
| `recipe/agent-account.md` | the zero-code recipe, in two shapes: the agent as a client of the installation with both OS switches off, or a computer of its own where the operating system is the wall | by hand |
| `PACKAGING.md` | the packaging facts verified from the official pages (Core's, unchanged) | by hand |

Regenerate after a change to a verb, a message, a bcomp table, a docs section the pack quotes, the shipped dictionaries, the guide or the stamp, from `sdb_ai\sd64`:

```
python agent-pack\mkpack.py --write
python gplbld\test-pack-units.py
```

The generator takes the tree and the docs checkout as arguments (`--tree DIR --docs DIR --out DIR --skill DIR --product NAME`). It reads the docs repository beside this one (`SDCore4WindowsSoloDocs`) and exits 2, saying so, when the checkout is missing. Line numbers in `src=path:line#hash` are locators that may lag after an edit elsewhere in the same file; the hash of the cited line is the identity and is what the check holds.

## Where this differs from SD Core's agent pack, and why

Solo is the single-user product; SD Core's pack was written for the full product and is the template. Every difference below is a fact about this product, not a choice of wording. The generator is Core's `mkpack.py` with five names and four branches, each marked `SOLO:` in the file.

| | SD Core for Windows' pack | Solo's pack | why |
|---|---|---|---|
| accounts | many; `create.account`, `modify.account`, group accounts, `sys:word:<word>` chunks for every account word | one account, `sduser`; **no account-word chunks** (`HAS_ACCOUNT_WORDS = False`); `create.account` and `logto` are "not in your VOC" | Solo has no `createa` and no `modifya` |
| walls | per-account gates, off by default, switched on by SDSYS (chunk `core:gates`) | `admin`, the two OS switches `sh` and `os` (off as delivered), the VOC, the global catalogue and the compiler's restricted names (chunk `core:walls`, quoted from Solo's `12-security` and `06b-operating-system-access` pages) | Solo has one account, so two switches on it and no gate words |
| the shell and the operating system | `sh`, `os.execute` and a path outside the account are each gated and refused as delivered, switched with `modify.account` | **two switches, off as delivered**: `sh` for the `sh` verb; `os` for `os.execute`, a path outside the account, the embedded Python and the editors that run outside SD; the administrator switches them with `set.os.access sh on` and the like. The guide shows each refusal, and says that a switch the user turned on is a fact and not a permission | the Solo OS switch (owner, 20 Oct 2026: two words like Core); the verb's name and shape are Solo's own, a listed deviation |
| the administrator | SDSYS, entered by running SD elevated while signed in to Windows as SDSYS | `admin` and the administrator password, typed by the user in the session; the guide never has an agent type or look for it | Solo has no SDSYS user |
| writing the VOC | `voc-on` gate, status 3035 | `admin`, status 3035, and the run-time text says "(Possible full disk?)", which the guide warns is the wall and not a disk | the same kernel test, a different key |
| compiling and cataloguing | `bp-on` gate; an account without it cannot compile | always allowed; `catalog ... global` is refused | no per-account gates; the global catalogue is the administrator's |
| the way in | ssh to port 22 forced into `sd`, or the API on 4247 | `sd-solo` on a pipe whose first line is the account password, or ssh to Solo's own port 4251, or the API on 4249 | Solo's own ports and sign-on |
| the recipe | an account and a Windows user of its own on the same computer | **two shapes**: a client of the installation with both switches off (the data it reaches is the account's), or **a computer or virtual machine of its own** when it needs a switch or must not see the account: one SD runs on a computer, and one account holds everything | one SD on a computer (its ports are machine-wide) |
| the guide's two lanes | an administrator lane and ordinary accounts (`as=` on a block) | one lane, a plain session of `sduser` that has not typed `admin`, both switches off; a block that names `as=` is refused | there is one account and no gate words |
| the skill | `sd-core` | `sd-core-solo` | two skills may be installed side by side |
| the VOC layers in the pack | `newvoc` for every account, `voc_template` for SDSYS, `newvoc.mods` on top | the one account's VOC is `newvoc` whole | Solo has no `newvoc.mods` |
| the docs the generator reads | `SDCore4WindowsDocs` (`User`, `Administrator`) | `SDCore4WindowsSoloDocs` (`User`, `GettingStarted`) | Solo's docs are a separate repository |
| installed | the guide and pack, as text, under SDSYS | not installed | as SD Core Solo for Linux |

Not different: the dialect itself. The guide's Part A, its worked examples (Part C), the table of what SD lacks (B6) and the rosters hold for Solo as they stand; on SD Core Solo for Linux every row of the Solo guide was run and holds. They were not run on Windows Solo: the guide's sandbox is a Linux tool.
