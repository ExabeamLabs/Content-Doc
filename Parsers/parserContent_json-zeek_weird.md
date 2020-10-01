#### Parser Content
```Java
{
Name = json-zeek_weird
  Product = Zeek Network Security Monitor
  DataType = "network-alert"
  Conditions = [ """ zeek_weird """, """"id.orig_h""", """"id.resp_h""" ]
  Fields = ${BroParserTemplates.json-zeek-activity.Fields}[
    """"name\\?"+:\\?"+({alert_name}[^"\\]+)""",
    """"peer\\?"+:\\?"+({src_host}[^"\\]+)"""
  ]
}
```