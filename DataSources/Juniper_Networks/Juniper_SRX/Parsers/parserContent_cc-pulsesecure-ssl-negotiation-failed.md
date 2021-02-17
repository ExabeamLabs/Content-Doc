#### Parser Content
```Java
{
Name = cc-pulsesecure-ssl-negotiation-failed
  DataType = "network-connection-failed"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """"PulseSecure:"""", """SSL negotiation failed""", """Reason:""" ]
  Fields = ${JuniperParserTemplates.cef-pulsesecure-vpn-events.Fields} [
    """SSL negotiation failed while client at source IP \'({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\' was trying to connect to \'({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\'.""",
    """Reason:\s+\'({failure_reason}[^\']+)\'"""
  ]
}
```