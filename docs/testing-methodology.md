# microauthd
---
## Testing Methodology
---

#### Introduction

microauthd is tested via a mix of Xunit internal tests that hammer the service layer, which indirectly tests most aspects of the data layer. For complete end-to-end coverage, there is also a python test suite. Since microauthd maintains feature parity across it's cli tool `mad` and its JSON/HTTP APIs, we can get full route coverage testing by using an external test runner (python/pytest), which can also use curl to hit our token endpoints. It is true that there's some overlap, but the python testing is 2-for-1, because we get to test the `mad` cli tool in addition to the endpoints themselves. 

There is currently no automated testing or otherwise of the web gui- it is hand tested. Perhaps we'll look to add some automated testing in the future.