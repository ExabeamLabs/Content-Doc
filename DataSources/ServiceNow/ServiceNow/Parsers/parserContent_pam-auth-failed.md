#### Parser Content
```Java
{
Name = pam-auth-failed
  DataType = "authentication-failed"
  Conditions = [ """Transaction: login""", """PAM-CMN-2179:""", """gkpsyslog""" ]
  Fields = ${PamParserTemplates.pam-authentication.Fields}[
    """({event_name}LDAP authentication failed)""",
    """({failure_reason}The user entered an incorrect password.)""",
  ]
}
pam-authentication = {
    Vendor = CA Technologies
    Product = CA Privileged Access Manager Server Control
    Lms = Direct
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
      """\screated\s{0,100}=\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """\sUser\s{0,100}:\s{0,100}CN=({user_fullname}[^,]{1,2000}),\s{0,100}({user_ou}.+?),\s{0,100}Transaction:""",
      """\sUser\s{0,100}:\s{0,100}({user_email}[^,@]{1,2000}@[^,]{1,2000})""",
      """\sUser\s{0,100}:\s{0,100}(?:unknown|({user}[^@=,]{1,2000})),\s{0,100}Transaction:""",
      """\sUser Group\s{0,100}:\s{0,100}CN=({group_name}[^,]{1,2000}),\s{0,100}({group_ou}.+?),\s{0,100}Port:""",
      """\sNat\/Proxy IP\s{0,100}:\s{0,100}({src_ip}[a-fA-F\d.:]{1,2000})""",
      #"""\sDetails:[^;]{0,2000}:\s{1,100}({event_name}[^;]{1,2000}?)\s{0,100}(;|$)""",
      """\sPrivate IP\s{0,100}:\s{0,100}({src_ip}[a-fA-F\d.:]{1,2000})""",
      """\sSource IP\s{0,100}:\s{0,100}({src_ip}[a-fA-F\d.:]{1,2000})""",
      """(?i)\sDevice Name\s{0,100}:\s{0,100}(?:\- \-|({dest_host}[^,]{1,2000}))""",
      """\sPort\s{0,100}:\s{0,100}({dest_port}\d{1,100})""",
      """\sAccess/Protocol\s{0,100}:\s{0,100}(?:\- \-|({protocol}[^,]{1,2000}))""",
      """\sService/App\s{0,100}:\s{0,100}(?:\- \-|({app}[^,]{1,2000}))""",
    ]

```