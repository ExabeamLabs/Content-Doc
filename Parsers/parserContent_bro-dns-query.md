#### Parser Content
```Java
{
Name = bro-dns-query
  Product = Bro
  DataType = "dns-query"
  Conditions = [ """"id.orig_h""", """"id.resp_h""", """"_path":"dns_red"""", """"query":"""", """"qtype_name":"""" ]
  Fields = ${BroParserTemplates.json-bro-activity.Fields}[
    """"query":"({query}[^"]+)""",
    """"qtype_name":"({query_type}[^"]+)""",
  ]
}
```