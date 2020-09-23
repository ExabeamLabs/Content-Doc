#### Parser Content
```Java
{
Name = bro-dhcp-1
  Product = Zeek Network Security Monitor
  DataType = "dhcp"
  Conditions = [ """"id.orig_h""", """"id.resp_h""", """"assigned_ip""", """"lease_time""" ]
  Fields = ${BroParserTemplates.json-bro-activity.Fields}[
    """"assigned_ip":\s*"({assigned_ip}[a-fA-F\d.:]+)""",
    """"lease_time":\s*({lease_time}[\d\.]+)""",
    """"trans_id":\s*({trans_id}\d+)""",
  ]
}
```