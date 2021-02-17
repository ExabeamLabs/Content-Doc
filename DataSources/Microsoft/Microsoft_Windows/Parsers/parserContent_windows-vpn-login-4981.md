#### Parser Content
```Java
{
Name = windows-vpn-login-4981
  DataType = "vpn-login"
  Conditions = [ """(4981)""", """[WIN]""", """Microsoft-Windows-Security-Auditing""" ]
  Fields = ${WinParserTemplates.windows-vpn-direct-access.Fields} [
    """({event_name}IPsec main mode and extended mode security associations were established)""",
    """Remote Endpoint: Principal Name:\s*(\w+(\\+|\/+))?({dest_host}[^\s]+)\s""",
    """Remote Principal Name:\s*(({domain}[^\\]+)\\)?({user}[^\s]+)\s""",
  ]
}
```