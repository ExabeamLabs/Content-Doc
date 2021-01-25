#### Parser Content
```Java
{
Name = json-zeek_dhcp
  Product = Zeek Network Security Monitor
  DataType = "dhcp"
  Conditions = [ """ zeek_dhcp """, """msg_type""" ]
  Fields = ${BroParserTemplates.json-zeek-activity.Fields}[
    """"mac"+:"+({src_mac}[^"]+)""",
    """"ts"+:({time}\d+)""",
    """"uids"+:\["+({uids}[^"]+)""",
    """"msg_types"+:\["+({dhcp_type}[^"]+)""",
  ]
}
```