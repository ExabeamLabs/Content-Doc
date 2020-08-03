#### Parser Content
```Java
{
Name = bluecoat-proxy-11
  DataType = "network-connection"
  Conditions = [ """ PROXIED """, """ TCP_""" ]
  Fields = ${BlueCoatParserTemplates.bluecoat-proxy.Fields}[
    """(-|({failure_reason}\S+))\s+PROXIED"""
  ]
}
```