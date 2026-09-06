# Token Theft & Conditional Access Bypass (Post-2023 Techniques)

_Author: Community addendum (2026)_
_Created: September 2026_

> **Scope note:** This is a light-touch community addendum, not an original chapter by the playbook's authors. It documents token-abuse techniques that became prominent industry-wide after the original chapters were written, and deliberately keeps things brief. For the in-depth treatment of Primary Refresh Token (PRT) and refresh token (RT) replay — including FOCI background, TokenTactics usage, and IPC/MDE detections — see [Chapter 5: Replay of Primary Refresh (PRT) and other issued tokens](ReplayOfPrimaryRefreshToken.md). This addendum only adds what is *not* already covered there.

*MITRE ATT&CK: [Steal Application Access Token (T1528)](https://attack.mitre.org/techniques/T1528/), [Steal Web Session Cookie (T1539)](https://attack.mitre.org/techniques/T1539/), [Phishing (T1566)](https://attack.mitre.org/techniques/T1566/)*

- [Token Theft & Conditional Access Bypass (Post-2023 Techniques)](#token-theft--conditional-access-bypass-post-2023-techniques)
  - [1. Refresh Token / FOCI Abuse](#1-refresh-token--foci-abuse)
  - [2. Device-Code-Flow Phishing (AiTM / Consent-style)](#2-device-code-flow-phishing-aitm--consent-style)
  - [3. PRT Abuse: What's New Since Chapter 5](#3-prt-abuse-whats-new-since-chapter-5)
  - [Detection Approach](#detection-approach)
  - [Illustrative KQL Sketch](#illustrative-kql-sketch)
  - [Mitigation Notes](#mitigation-notes)
  - [References](#references)

## 1. Refresh Token / FOCI Abuse

**Attack scenario:** Chapter 5 already covers refresh token (RT) theft and replay across Family of Client IDs (FOCI) applications in detail (see [Refresh Token (RT)](ReplayOfPrimaryRefreshToken.md#refresh-token-rt)). What is worth calling out separately here is that FOCI abuse has continued to be a favorite technique in commodity phishing kits and AiTM toolkits (e.g. Evilginx-style reverse proxies) since 2023: once *any* FOCI client's refresh token is captured, an attacker can mint access tokens for a wide range of first-party Microsoft applications (Graph, Teams, SharePoint, Azure management) without re-prompting the user, because FOCI membership is designed to make refresh tokens interchangeable across the family. This makes a single stolen RT from a low-value app (e.g. a mobile client) a pivot point into high-value Microsoft 365 and Azure resources.

## 2. Device-Code-Flow Phishing (AiTM / Consent-style)

**Attack scenario:** The OAuth 2.0 device authorization grant ("device code flow") is intended for input-constrained devices (e.g. smart TVs, CLI tools). An adversary abuses it as a phishing primitive:

1. The attacker initiates a device code request against Microsoft identity platform (`/oauth2/v2.0/devicecode`) for a legitimate first-party or FOCI client ID.
2. The attacker sends the victim a lure (email, Teams message, chat) containing the generated `user_code` and the `https://microsoft.com/devicelogin` (or tenant-branded) URL, framed as an urgent action (e.g. "verify your Teams session", "join this meeting").
3. The victim completes normal interactive sign-in (including MFA) at the legitimate Microsoft URL, believing they are authenticating their own device or session.
4. Because the attacker's polling client — not the victim's browser — holds the device code, the attacker's session receives the resulting access/refresh token pair once the victim finishes sign-in. Since the user completed real MFA, this bypasses Conditional Access controls that only check for a "successful MFA claim" without also validating device state or session context.

This is functionally an adversary-in-the-middle (AiTM) technique, but it does not require a reverse proxy or a spoofed login page — the victim authenticates on the genuine Microsoft domain, which makes it resistant to URL/domain-based phishing awareness training and to browser anti-phishing filters.

## 3. PRT Abuse: What's New Since Chapter 5

Chapter 5 thoroughly covers PRT theft via exfiltrated transport/session keys and TPM-bypass scenarios (see [Primary Refresh Token (PRT)](ReplayOfPrimaryRefreshToken.md#primary-refresh-token-prt)). Beyond that existing coverage, two developments are worth flagging for readers revisiting this topic:

- **PRT abuse via device-code and cross-device sign-in flows**: rather than extracting PRT material directly from a compliant device, attackers increasingly try to get a *new*, attacker-controlled device registered or PRT-equivalent trust established by riding a phished interactive sign-in (see device-code phishing above) or by abusing self-service device registration where insufficiently restricted. The goal is the same as classic PRT theft (a long-lived, high-trust token bound to "a" device) but the acquisition path avoids touching the victim's real device or TPM at all.
- **Continuous Access Evaluation (CAE) interactions**: as CAE has broadened since the original chapter was written, defenders should not assume that CAE-capable access tokens are automatically revoked on risk detection for every workload — the original chapter's note on SharePoint/OneDrive CAE-trigger gaps (see [Access Token (AT)](ReplayOfPrimaryRefreshToken.md#access-token-at)) remains relevant and should be re-validated against current CAE workload coverage before an exercise, since Microsoft has continued to expand which signals and workloads participate in CAE.

No new PRT theft mechanic is introduced here — this section exists purely to point readers to what Chapter 5 already covers and flag where the threat landscape has shifted around it.

## Detection Approach

- **Device code flow abuse**: Azure AD / Entra ID sign-in logs record device-code-flow sign-ins with `authenticationProtocol == "deviceCode"` (or the corresponding value in the `SigninLogs` schema). A sudden increase in device-code sign-ins for a tenant that does not normally use CLI/IoT-style authentication, or device-code sign-ins immediately followed by high-privilege Graph/Exchange/SharePoint activity from a new device/IP, is a strong signal.
- **FOCI pivoting**: correlate `NonInteractiveSignIns`/`SigninLogs` events where a refresh token issued to one client ID (e.g. a low-privilege FOCI app) is followed within a short window by token issuance to a different, higher-value FOCI client ID for the same user/session, from the same or an unexpected IP/device — consistent with the pivoting pattern already illustrated in Chapter 5's FOCI walkthrough.
- **PRT-via-new-device**: watch for a new device registration/join immediately followed by PRT issuance and high-privilege activity, especially where the registering device does not match expected compliance/enrollment baselines — this extends the existing MDE/IPC detections described in Chapter 5's [Suspicious authentication and activity to access PRT](ReplayOfPrimaryRefreshToken.md#suspicious-authentication-and-activity-to-access-prt) section rather than replacing them.

## Illustrative KQL Sketch

> ⚠️ **This is an illustrative sketch only.** It has not been run or validated against a live tenant or a live Sentinel workspace, field names and table availability vary by tenant configuration/licensing and by Microsoft schema changes since this was written, and it is **not** tested or production-ready. Validate every field name, table, and threshold against your own Sentinel/Log Analytics schema (`SigninLogs`, `AADNonInteractiveUserSignInLogs`, or the ASIM `imAuthentication` normalized schema, depending on your environment) before using it in any exercise or production detection.

```kql
// Illustrative sketch: device-code sign-ins followed by rapid FOCI-style token reuse.
// Validate table/column names against your own schema before use.
SigninLogs
| where TimeGenerated > ago(1d)
| where AuthenticationProtocol =~ "deviceCode"                 // confirm this value exists in your schema/version
| project TimeGenerated, UserPrincipalName, AppId, AppDisplayName, IPAddress, DeviceDetail
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(1d)
    | project TimeGenerated2 = TimeGenerated, UserPrincipalName, AppId2 = AppId, AppDisplayName2 = AppDisplayName, IPAddress2 = IPAddress
) on UserPrincipalName
| where TimeGenerated2 between (TimeGenerated .. TimeGenerated + 15m)
| where AppId != AppId2                                        // token reused across a different client/app shortly after
| project UserPrincipalName, DeviceCodeApp = AppDisplayName, FollowOnApp = AppDisplayName2, IPAddress, IPAddress2, TimeGenerated, TimeGenerated2
```

## Mitigation Notes

- Where device-code flow is not a required business scenario, block or restrict it via Conditional Access (`Authentication Flows` condition, available in current Entra ID Conditional Access) rather than relying on user awareness alone.
- Pair MFA requirements with device compliance/hybrid-join or token-protection (where available) as a Conditional Access grant control, so a phished-but-real MFA claim alone is insufficient — this directly addresses the device-code phishing bypass described above.
- Continue to follow the PRT/RT mitigations already documented in Chapter 5 (TPM enforcement, device compliance, refresh token revocation processes) — nothing here supersedes them.

## References

- [Microsoft: Device code flow abuse — attacks and mitigations](https://www.microsoft.com/en-us/security/blog/) *(search current Microsoft Security blog / Threat Intelligence for the latest device-code-phishing advisories — specific post URLs move over time)*
- [Family of Client IDs (FOCI) research — secureworks](https://github.com/secureworks/family-of-client-ids-research) *(also referenced in Chapter 5)*
- [MITRE ATT&CK: Steal Application Access Token (T1528)](https://attack.mitre.org/techniques/T1528/)
- [MITRE ATT&CK: Phishing (T1566)](https://attack.mitre.org/techniques/T1566/)
- [MITRE ATT&CK Updates](https://attack.mitre.org/resources/updates/) — check for the current release, since this playbook otherwise pins to v11
