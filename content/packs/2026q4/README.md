# Autumn 2026 scenario pack

Four hand-authored, branching tabletop scenarios on the library environments,
each with a decision card and a coaching note on every option, an executive
communications scene, state-driven endings, and impact figures on the
branches. They are the content a Team, Education or Enterprise licence
installs from the Members page.

| File | Library environment | Story | Scenes |
|---|---|---|---|
| `halvorsen-lathe.yaml` | `manufacturer` | Supplier-portal web shell to design-vault extortion; isolate the plant or lose the MES | 10 |
| `clearwater-stillwater.yaml` | `water_utility` | Phished controls engineer, an off-hours HMI session, a dosing set-point write the interlock catches, if nobody trusts the screen | 9 |
| `marrow-ballot-box.yaml` | `county` | VPN password spray to ransomware in election week; dispatch isolated by design, backups on the domain | 8 |
| `northgate-cold-archive.yaml` | `university` | MFA fatigue on a research director, a registered rogue device, an export-controlled dataset leaving, the health centre adjacent | 8 |

Every active scene carries a declared decision (`meta.decision`) whose
options name the branch they take (`trigger`), so the room's answer drives
the story in a facilitated run and the autopilot proctor drives it in solo
play. Endings are chosen on accumulated state (`condition`), not only on the
last answer: telling the regulator early in Stillwater changes which ending
a late mistake lands on; containing at the file server in Ballot Box skips
the domain rebuild entirely.

## Signing and publishing

Only the vendor key signs a pack. From the repository root, with the key
file outside the repository:

```bash
python tools/build_pack.py scenarios \
    --key-file /path/to/vendor-license-2026.key \
    --id moosearsenal-2026q4 --name "Autumn 2026 scenario pack" \
    --version 2026.10 --publisher "Moose Arsenal" \
    content/packs/2026q4/halvorsen-lathe.yaml:manufacturer \
    content/packs/2026q4/clearwater-stillwater.yaml:water_utility \
    content/packs/2026q4/marrow-ballot-box.yaml:county \
    content/packs/2026q4/northgate-cold-archive.yaml:university \
    > autumn-2026.gpack
python tools/build_pack.py inspect autumn-2026.gpack
```

The `:key` after each file names the library environment the scenario was
written for; install binds each scenario to the organisation's copy of that
environment, stamping it if it does not exist yet. Attach the `.gpack` to
the GitHub release and note it in the changelog. Customers install it from
the Members page; inspecting a pack needs no licence, installing needs the
content subscription (Team and above).

## Editing

The files are the scenario YAML the console exports, so a pack scenario can
be imported into any organisation for editing (`POST /api/scenarios/import`
or the editor) and exported back. `backend/tests/test_e_content_pack.py`
checks every file: the graph validates, every active scene has a decision
with notes on every option, every option's trigger is a branch of its
scene, every target asset exists in the named environment, and each
scenario plays to an ending on the blue and executive sides.
