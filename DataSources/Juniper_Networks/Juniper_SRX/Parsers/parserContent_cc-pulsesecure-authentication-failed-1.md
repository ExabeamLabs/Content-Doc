#### Parser Content
```Java
{
Name = cc-pulsesecure-authentication-failed-1
  DataType = "authentication-failed"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """"PulseSecure:"""", """Active Directory authentication server""", """Domain trust check failed.""" ]
  Fields = ${JuniperParserTemplates.cef-pulsesecure-vpn-events.Fields} [
    """({additional_info}Active Directory authentication server \'({auth_server}[^\']+)\': ({failure_reason}Domain trust check failed). Administrator may need to rejoin to the domain.)"""
  ]
}
```