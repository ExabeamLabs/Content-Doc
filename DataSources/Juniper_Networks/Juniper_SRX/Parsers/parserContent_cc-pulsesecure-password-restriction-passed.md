#### Parser Content
```Java
{
Name = cc-pulsesecure-password-restriction-passed
  DataType = "authentication-successful"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """"PulseSecure:"""", """Password realm restrictions successfully passed""" ]
  Fields = ${JuniperParserTemplates.cef-pulsesecure-vpn-events.Fields} [
    """Password realm restrictions successfully passed for\s+({user}[^\/]+)?\/({realm}[^\s]+) , with certificate \'({safe_value}[^\']+)\'""",
    """\'CN\\=({user_email}[^@',]+@[^,']+)"""
  ]
}
```