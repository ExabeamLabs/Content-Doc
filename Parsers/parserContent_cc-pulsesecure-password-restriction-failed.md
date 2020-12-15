#### Parser Content
```Java
{
Name = cc-pulsesecure-password-restriction-failed
  DataType = "authentication-failed"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """"PulseSecure:"""", """Testing Password realm restrictions failed""" ]
  Fields = ${JuniperParserTemplates.cef-pulsesecure-vpn-events.Fields} [
    """({failure_reason}Testing Password realm restrictions failed) for\s+({user}[^\/]+)?\/({realm}[^\s]+) , with certificate \'({safe_value}[^\']+)\'""",
    """\'CN\\=({user_email}[^@',]+@[^,']+)"""
  ]
}
```