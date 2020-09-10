#### Parser Content
```Java
{
Name = sonicwall-network-alert-19
  Product = Sonicwall
  Lms = Direct
  DataType = "network-alert"
  Conditions = [ """id=""", """firewall""", """ c=""", """ fw=""", """Policy: CFS Default Policy""" ]
  Fields = ${SonicwallParserTemplates.sonicwall-firewall.Fields} [
    """appName="({app}[^"]+)"""",
    """Category="({category}[^"]+)"""",
    """rule="({rule}[^"]+)"""",
    """note="({additional_info}[^"]+?)\s*"""",
  ]
}
```