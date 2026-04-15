---
tags:
  - "#Regex"
date: "{{date}}"
---
# Regex

## Charsets

`[abc]` - will match `a`, `b` and `c`

`[abc]zz` - will match `azz`, `bzz` and `czz`
`[a-c]zz` is the same as above

`[a-cx-z]zz` - will match `azz`, `bzz`, `czz`, `xzz`, `yzz` and `zzz`

`[a-zA-Z]` - will match any **single** letter (lower or uppercase)

`file[1-3]` - will match `file1`, `file2`, `file3`

**Exclude character from a charset with `^` and include everything else:**
`[^k]ing` - will match `ring`, `sing`, `$ing`, but not `king`
`[^a-c]at` - will match `fat` and `hat`, but not `bat` or `cat`

>