#### Parser Content
```Java
{
Name = sonicwall-network-alert-18
  Product = Sonicwall
  Vendor = Sonicwall
  Lms = Direct
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  DataType = "network-alert"
  Conditions = [ """id=""", """firewall""", """ c=""", """ fw=""", """Administrator logged out""" ]
  Fields = ${SonicwallParserTemplates.sonicwall-firewall.Fields} [
    """\sfw=({firewall}[a-fA-F\d.:]+)""",
  ]
}
```