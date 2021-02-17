#### Parser Content
```Java
{
Name = cc-pulsesecure-authentication-successful
  DataType = "authentication-successful"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """"PulseSecure:"""", """Primary authentication successful""" ]
  Fields = ${JuniperParserTemplates.cef-pulsesecure-vpn-events.Fields} [
    """Primary authentication successful for\s+(({domain}[^\\]+)\\+)?({user}[^@\s\\\/]+)(\/({realm}[^\s]+))\s+from\s+({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
}
```