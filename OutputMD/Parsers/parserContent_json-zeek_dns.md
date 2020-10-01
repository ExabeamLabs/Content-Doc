#### Parser Content
```Java
{
Name = json-zeek_dns
  Product = Zeek Network Security Monitor
  DataType = "dns-query"
  Conditions = [ """"id.orig_h""", """"id.resp_h""", """ zeek_dns """ ]
  Fields = ${BroParserTemplates.json-zeek-activity.Fields}[
    """"query"+:"+({query}[^"]+)""",
    """"qtype_name"+:"+({query_type}[^"]+)""",
    """"proto\\?"+:\\?"+({protocol}[^"]+)""",
  ]
}
```