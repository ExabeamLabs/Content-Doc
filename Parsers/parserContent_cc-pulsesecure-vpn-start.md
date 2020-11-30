#### Parser Content
```Java
{
Name = cc-pulsesecure-vpn-start
  DataType = "vpn-start"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """"PulseSecure:"""", """VPN Tunneling: Session started for user""" ]
  Fields = ${JuniperParserTemplates.cef-pulsesecure-vpn-events.Fields} [
    """\shostname\s+({src_host}[^"\s]+)""",
    """Session started for user with IPv4 address ({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
}
```