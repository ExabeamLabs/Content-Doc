#### Parser Content
```Java
{
Name = bro-radius-1
  Product = Bro
  DataType = "nac-logon"
  TimeFormat = "epoch_sec"
  Conditions = [ """"id.orig_h""", """"id.resp_h""", """"username""", """"framed_addr""", """"result""", """"ttl""" ]
  Fields = ${BroParserTemplates.json-bro-activity.Fields}[
    """"ts":({time}\d+)""",
    """"username":\s*"({user}[^"]+)""",
    """"framed_addr":\s*"({framed_addr}[a-fA-F\d.:]+)""",
    """"result":\s*"({outcome}[^"]+)""",
    """"ttl":\s*({response_ttl}[\d\.]+)""",
  ]
}
```