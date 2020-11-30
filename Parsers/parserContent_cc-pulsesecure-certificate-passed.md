#### Parser Content
```Java
{
Name = cc-pulsesecure-certificate-passed
  DataType = "authentication-successful"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """"PulseSecure:"""", """Certificate realm restrictions successfully passed""" ]
  Fields = ${JuniperParserTemplates.cef-pulsesecure-vpn-events.Fields} [
    """Certificate realm restrictions successfully passed for\s+({user}[^\/]+)?\/({realm}[^\s]+) , with certificate \'({safe_value}[^\']+)\'""",
    """\'CN\\=({user_email}[^@',]+@[^,']+)"""
  ]
}
```