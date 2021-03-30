#### Parser Content
```Java
{
Name = windows-vpn-login-failed-4654
  DataType = "failed-vpn-login"
  Conditions = [ """(4654)""", """[WIN]""", """Microsoft-Windows-Security-Auditing""" ]
  Fields = ${WinParserTemplates.windows-vpn-direct-access.Fields} [
    """({event_name}An IPsec quick mode negotiation failed)"""
    """({outcome}failed)""",
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
    """({log_type}Microsoft-Windows-Security-Auditing)""",
    """Local Network Address:\s*({src_ip}[^\s]+)\s""",
    """Remote Network Address:\s*({dest_ip}[^\s]+)\s""",
  ]

```