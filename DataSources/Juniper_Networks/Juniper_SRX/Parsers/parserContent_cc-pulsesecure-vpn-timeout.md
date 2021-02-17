#### Parser Content
```Java
{
Name = cc-pulsesecure-vpn-timeout
  DataType = "vpn-end"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """"PulseSecure:"""", """Session timed out for""", """ (session:""" ]
  Fields = ${JuniperParserTemplates.cef-pulsesecure-vpn-events.Fields} [
    """Session timed out for ({user}[^\/]+)\/"""
  ]
}
```