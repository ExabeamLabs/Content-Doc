#### Parser Content
```Java
{
Name = sonicwall-network-alert-1
  Product = Sonicwall
  DataType = "network-alert"
  Conditions = [ """id=""", """firewall""", """msg="Invalid SNMP""", """c=0""" ]
  Fields = ${SonicwallParserTemplates.sonicwall-firewall.Fields}[
    """\snote="({additional_info}[^"]+)""",
  ]
}
```