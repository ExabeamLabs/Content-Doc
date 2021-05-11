#### Parser Content
```Java
{
Name = beyondtrust-pi-app-login
  DataType = "app-login"
  Conditions = [ """CEF:""", """|Privileged Identity|""", """|EVENT_ID_WEBAPP_LOGIN|""" ]
  Fields = ${BeyondTrustParserTemplates.beyondtrust-pi-events.Fields}[
    """Impersonating user (({target_domain}[^\\]+)(\\)+)?({target_user}[^\s)]+)\)"""
]
}
beyondtrust-pi-events = {
  Vendor = BeyondTrust
  Product = BeyondTrust Privileged Identity
  Lms = Direct
  TimeFormat = "MMM dd yyyy HH:mm:ss" 
  Fields = [
    """\d\d:\d\d:\d\d ({host}[\w\-.]+) CEF""",
    """rt=({time}\w{3}\s\d\d\s\d\d\d\d\s\d\d:\d\d:\d\d)""",
    """msg=({additional_info}.+?)\s{1,100}(\w+=|$)""",
    """dntdom=\[?({domain}.+?)\]?\s{1,100}(\w+=|$)""",
    """duser=(\\)*((?i)(user|admin|administrator)|({user}.+?))\s{1,100}(\w+=|$)""",
    """cs3=({src_ip}[A-Fa-f:\d.]+)""",
    """CEF:\d{1,100}\|([^\|]+\|){3}({event_name}[^\|]+)\|""",
    """cs1=.+?({outcome}Success|Failure)"""
  ]

```