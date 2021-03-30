#### Parser Content
```Java
{
Name = windows-vpn-login-4979
  DataType = "vpn-login"
  Conditions = [ """(4979)""", """[WIN]""", """Microsoft-Windows-Security-Auditing""" ]
  Fields = ${WinParserTemplates.windows-vpn-direct-access.Fields} [
    """({event_name}IPsec main mode and extended mode security associations were established)""",
    """Remote Endpoint: Principal Name:\s*(\w+(\\+|\/+))?({dest_host}[^\s]+)\s""",
    """Remote Principal Name:\s*(({domain}[^\\]+)\\)?({user}[^\s]+)\s""",
  ]
}
windows-vpn-direct-access = {
  Vendor = Microsoft
  Product = Microsoft DirectAccess
  Lms = Syslog
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Fields = [
    """:\d\d\s+({host}.+?)\s*EvntSLog""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """\(({event_code}\d+)\)""",
    """({event_type}Microsoft-Windows-Security-Auditing)""",
    """Local Network Address:\s*({src_ip}[^\s]+)\s""",
    """Remote Network Address:\s*({dest_ip}[^\s]+)\s""",
  ]

```