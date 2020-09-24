#### Parser Content
```Java
{
Name = fortinet-ssl-failed-vpn-login
  DataType = "failed-vpn-login"
  TimeFormat = "yyyy-MM-dd 'time='HH:mm:ssZ"
  Conditions = [ """action="ssl-login-fail"""", """subtype="vpn"""" ]
  Fields = ${FortinetParserTemplates.fortinet-ssl-vpn.Fields} [
    """reason="({failure_reason}[^"]+)""",
  ]
}
```