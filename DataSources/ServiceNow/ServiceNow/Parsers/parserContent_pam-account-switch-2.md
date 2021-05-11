#### Parser Content
```Java
{
Name = pam-account-switch-2
  DataType = "account-switch"
  Conditions = [ """Transaction: xsso""", """PAM-PRX-0016:""", """, Access/Protocol:""" ]
  Fields = ${PamParserTemplates.pam-authentication.Fields}[
    """({event_name}Executed ""sudo su -"" using transparent login)""",
  ]
}
pam-authentication = {
    Vendor = CA Technologies
    Product = CA Privileged Access Manager Server Control
    Lms = Direct
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Fields = [
      """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
      """\screated\s{0,100}=\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """\sUser\s{0,100}:\s{0,100}CN=({user_fullname}[^,]+),\s{0,100}({user_ou}.+?),\s{0,100}Transaction:""",
      """\sUser\s{0,100}:\s{0,100}({user_email}[^,@]+@[^,]+)""",
      """\sUser\s{0,100}:\s{0,100}(?:unknown|({user}[^@=,]+)),\s{0,100}Transaction:""",
      """\sUser Group\s{0,100}:\s{0,100}CN=({group_name}[^,]+),\s{0,100}({group_ou}.+?),\s{0,100}Port:""",
      """\sNat\/Proxy IP\s{0,100}:\s{0,100}({src_ip}[a-fA-F\d.:]+)""",
      #"""\sDetails:[^;]*:\s{1,100}({event_name}[^;]+?)\s{0,100}(;|$)""",
      """\sPrivate IP\s{0,100}:\s{0,100}({src_ip}[a-fA-F\d.:]+)""",
      """\sSource IP\s{0,100}:\s{0,100}({src_ip}[a-fA-F\d.:]+)""",
      """(?i)\sDevice Name\s{0,100}:\s{0,100}(?:\- \-|({dest_host}[^,]+))""",
      """\sPort\s{0,100}:\s{0,100}({dest_port}\d{1,100})""",
      """\sAccess/Protocol\s{0,100}:\s{0,100}(?:\- \-|({protocol}[^,]+))""",
      """\sService/App\s{0,100}:\s{0,100}(?:\- \-|({app}[^,]+))""",
    ]

```