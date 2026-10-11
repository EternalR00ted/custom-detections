## What this changes

<!-- One or two sentences. For a rule: what it detects and why. -->

## Checklist

- [ ] Rule files are named after their `id`, and no rule file is deleted or renamed (retire it instead)
- [ ] Each rule's query returns `Timestamp`, `DeviceId`, `ReportId` and `DeviceName`
- [ ] Rule checks passed: static, compile, and zero hits over 3 days of production data (or `noise-reviewed-<commit>` after checking every hit)
- [ ] Read the red-side review and the model jury in the Rule checks comment
- [ ] If the rule lists lab tests: queued **Lab detonation**, read the fire plan, approved it, and every test was caught
- [ ] Changes to `config/atomics.yaml` add tests by hand, pinned to one commit with a SHA-256
