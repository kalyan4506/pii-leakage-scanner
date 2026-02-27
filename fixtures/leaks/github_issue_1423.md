## Bug: password reset emails going to wrong person

**Environment**
- prod-us-east-1
- commit: `9f3c0ab`

**Steps**
1. Customer says they are "Alice Smith" (alice.smith@example.com, +1-555-014-2233)
2. Reset link was sent to: `a.smith+vip@example.net` (should not happen)

**Logs**