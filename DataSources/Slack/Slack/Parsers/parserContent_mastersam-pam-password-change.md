#### Parser Content
```Java
{
Name = mastersam-pam-password-change
  DataType = "password-change"
  Conditions = [ """ Activity:reset_password_account """ ]
  Fields = ${MasterSAMParserTemplates.mastersam-pam-events.Fields} [
    """account=({target_user}[^"\s]+)""",
  ]
}
mastersam-pam-events = {
  Vendor = MasterSAM
  Product = MasterSAM PAM
  Lms = Direct
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Fields = [
    """({host}[\w\-.]+)\s+Event Time:\s*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)""",
    """\WUser:\s*(({domain}[^\\\s]+)\\+)?({user}[^\\\s]+)""",
    """\Wname=({dest_host}[\w\-.]+)\s+(\w+=|$)""",
    """\Whost=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wprotocol=({protocol}.+?)\s+(\w+=|$)""",
    """\Wstatus=({outcome}.+?)\s+(\w+=|$)""",
    """\Wfailed_message=({failure_reason}.+?)\s+(\w+=|$)""",
    """\WActivity:\s*({activity}.+?)\s+User:""",
  ]

```