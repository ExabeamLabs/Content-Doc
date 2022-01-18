#### Parser Content
```Java
{
Name = windows-vpn-login-4981
  DataType = "vpn-login"
  Conditions = [ """(4981)""", """[WIN]""", """Microsoft-Windows-Security-Auditing""" ]
  Fields = ${WinParserTemplates.windows-vpn-direct-access.Fields} [
    """({event_name}IPsec main mode and extended mode security associations were established)""",
    """Remote Endpoint: Principal Name:\s{0,100}(\w+(\\+|\/+))?({dest_host}[^\s]{1,2000})\s""",
    """Remote Principal Name:\s{0,100}(({domain}[^\\]{1,2000})\\)?({user}[^\s]{1,2000})\s""",
  ]

windows-vpn-direct-access = {
  Vendor = Microsoft
  Product = Microsoft DirectAccess
  Lms = Syslog
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Fields = [
    """:\d\d\s{1,100}({host}.+?)\s{0,100}EvntSLog""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """\(({event_code}\d{1,100})\)""",
    """({log_type}Microsoft-Windows-Security-Auditing)""",
    """Local Network Address:\s{0,100}({src_ip}[^\s]{1,2000})\s""",
    """Remote Network Address:\s{0,100}({dest_ip}[^\s]{1,2000})\s""",
  
}
```