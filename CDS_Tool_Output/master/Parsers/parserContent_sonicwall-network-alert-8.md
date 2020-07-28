#### Parser Content
```Java
{
Name = sonicwall-network-alert-8
  Product = Sonicwall
  Vendor = Sonicwall
  Lms = Direct
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  DataType = "network-alert"
  Conditions = [ """id=""", """firewall""", """ c=""", """ fw=""", """IKEv2 Responder""" ]
  Fields = ${SonicwallParserTemplates.sonicwall-firewall.Fields} [
    """\sfw=({firewall}[a-fA-F\d.:]+)""",
  ]
}
```