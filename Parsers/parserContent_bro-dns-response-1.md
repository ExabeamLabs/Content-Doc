#### Parser Content
```Java
{
Name = bro-dns-response-1
  Product = Zeek Network Security Monitor
  DataType = "dns-response"
  Conditions = [ """"id.orig_h""", """"id.resp_h""", """"_path":"dns_red"""", """"query":"""" ]
  Fields = ${BroParserTemplates.json-bro-activity.Fields}[
    """"query":"({query}[^"]+)""",
    """"rcode":({rcode}[^",]+)""",
    """"answers":\["({answers}[^"]+)""",
  ]
}
```