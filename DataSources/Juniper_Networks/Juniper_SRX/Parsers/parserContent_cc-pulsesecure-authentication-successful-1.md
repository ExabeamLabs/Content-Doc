#### Parser Content
```Java
{
Name = cc-pulsesecure-authentication-successful-1
  DataType = "authentication-successful"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """"PulseSecure:"""", """Secondary authentication successful""" ]
  Fields = ${JuniperParserTemplates.cef-pulsesecure-vpn-events.Fields} [
    """Secondary authentication successful for\s+(({domain}[^\\]+)\\+)?({user}[^@\s\\\/]+)(\/({realm}[^\s]+))\s+from\s+({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
}
```