#### Parser Content
```Java
{
Name = pam-auth-successful
  DataType = "authentication-successful"
  Conditions = [ """Transaction: login""", """logged in successfully""", """PAM-CMN-0917:""", """gkpsyslog""" ]
  Fields = ${PamParserTemplates.pam-authentication.Fields}[
    """({event_name}logged in successfully via ldap authentication.)""",
  ]
}
pam-authentication = {
    Vendor = CA Technologies
    Product = CA Privileged Access Manager Server Control
    Lms = Direct
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}\S+)""",
      """\screated\s*=\s*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """\sUser\s*:\s*CN=({user_fullname}[^,]+),\s*({user_ou}.+?),\s*Transaction:""",
      """\sUser\s*:\s*({user_email}[^,@]+@[^,]+)""",
      """\sUser\s*:\s*(?:unknown|({user}[^@=,]+)),\s*Transaction:""",
      """\sUser Group\s*:\s*CN=({group_name}[^,]+),\s*({group_ou}.+?),\s*Port:""",
      """\sNat\/Proxy IP\s*:\s*({src_ip}[a-fA-F\d.:]+)""",
      #"""\sDetails:[^;]*:\s+({event_name}[^;]+?)\s*(;|$)""",
      """\sPrivate IP\s*:\s*({src_ip}[a-fA-F\d.:]+)""",
      """\sSource IP\s*:\s*({src_ip}[a-fA-F\d.:]+)""",
      """(?i)\sDevice Name\s*:\s*(?:\- \-|({dest_host}[^,]+))""",
      """\sPort\s*:\s*({dest_port}\d+)""",
      """\sAccess/Protocol\s*:\s*(?:\- \-|({protocol}[^,]+))""",
      """\sService/App\s*:\s*(?:\- \-|({app}[^,]+))""",
    ]

```