# Profile Activation Schedule

HostsFileGet can store time-bound profile activation windows in the app config. This is a profile switcher for the saved configuration model only: it never writes `C:\Windows\System32\drivers\etc\hosts`, never registers a background task, and never installs parental-control policy.

## Config Shape

Schema `4` adds:

```json
{
  "profile_activation_schedule_version": 1,
  "profile_activation_fallback_id": "default",
  "profile_activation_schedule": [
    {
      "id": "kids-mon-tue-wed-thu-fri-1600-2000",
      "name": "Kids block hours",
      "profile_id": "kids",
      "days": ["mon", "tue", "wed", "thu", "fri"],
      "start_time": "16:00",
      "end_time": "20:00",
      "enabled": true
    }
  ]
}
```

Profile IDs must already exist in `profiles`. Invalid windows are dropped by the config sanitizer.

## Matching Rules

- Times are local 24-hour `HH:MM` values.
- Days accept `daily`, `weekdays`, `weekends`, or comma-separated weekday names.
- `start_time` is inclusive and `end_time` is exclusive.
- Overnight windows are allowed. A Friday `22:00-07:00` window matches late Friday night and early Saturday morning.
- If no enabled window matches, the fallback profile is the target.
- If no schedule is configured, the current active profile remains the target.

## CLI

Show the current schedule and target profile without writing:

```powershell
python hosts_editor.py --profile-schedule-list
python hosts_editor.py --profile-schedule-list --profile-schedule-at 2026-05-11T17:00:00
```

Add a schedule window:

```powershell
python hosts_editor.py --profile-schedule-add kids 16:00 20:00 --profile-schedule-days weekdays --profile-schedule-name "Kids block hours" --profile-schedule-fallback default
```

Evaluate and switch only the app config profile:

```powershell
python hosts_editor.py --profile-schedule-apply
python hosts_editor.py --profile-schedule-apply --profile-schedule-at 2026-05-11T17:00:00
```

`--profile-schedule-apply` writes the app config only when the target profile differs from the current active profile. It does not touch the system hosts file; use the normal reviewed save/update flows after inspecting the active config.

## GUI

Use **Tools > Profile Activation Schedule...** to inspect the active schedule and see whether the current time would require an app-config profile switch. The GUI report is read-only.

## Boundaries

- This is not a scheduler daemon. Users must run the CLI from Task Scheduler or another trusted automation layer if they want recurring evaluation.
- This is not a policy-enforcement feature. Local users with access to the app config can change schedules and profiles.
- This does not replace DNS, router, browser, or operating-system parental-control controls.
