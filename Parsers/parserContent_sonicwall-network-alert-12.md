#### Parser Content
```Java
{
Name = sonicwall-network-alert-12
  Product = Sonicwall
  Vendor = Sonicwall
  Lms = Direct
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  DataType = "network-alert"
  Conditions = [ """id=""", """firewall""", """ c=""", """ fw=""", """IPsec Tunnel status changed""" ]
  Fields = ${SonicwallParserTemplates.sonicwall-firewall.Fields} [
    """\sfw=({firewall}[a-fA-F\d.:]+)""",
  ]
}
```