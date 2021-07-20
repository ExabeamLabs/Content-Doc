#### Parser Content
```Java
{
Name = mastersam-pam-password-change
  DataType = "password-change"
  Conditions = [ """ Activity:reset_password_account """ ]
  Fields = ${MasterSAMParserTemplates.mastersam-pam-events.Fields} [
    """account=({target_user}[^"\s]{1,2000})""",
  ]
}
mastersam-pam-events = {
  Vendor = MasterSAM
  Product = MasterSAM PAM
  Lms = Direct
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Fields = [
    """({host}[\w\-.]{1,2000})\s{1,100}Event Time:\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100})""",
    """\WUser:\s{0,100}(({domain}[^\\\s]{1,2000})\\+)?({user}[^\\\s]{1,2000})""",
    """\Wname=({dest_host}[\w\-.]{1,2000})\s{1,100}(\w+=|$)""",
    """\Whost=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wprotocol=({protocol}.+?)\s{1,100}(\w+=|$)""",
    """\Wstatus=({outcome}.+?)\s{1,100}(\w+=|$)""",
    """\Wfailed_message=({failure_reason}.+?)\s{1,100}(\w+=|$)""",
    """\WActivity:\s{0,100}({activity}.+?)\s{1,100}User:""",
  ]

```