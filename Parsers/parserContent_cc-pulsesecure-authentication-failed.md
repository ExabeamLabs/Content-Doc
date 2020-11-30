#### Parser Content
```Java
{
Name = cc-pulsesecure-authentication-failed
  DataType = "authentication-failed"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """"PulseSecure:"""", """Primary authentication failed""" ]
  Fields = ${JuniperParserTemplates.cef-pulsesecure-vpn-events.Fields} [
    """({failure_reason}Primary authentication failed) for\s+(({domain}[^\\]+)\\+)?({user}[^@\s\\\/]+)(\/({realm}[^\s]+))\s+from\s+({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
}
```