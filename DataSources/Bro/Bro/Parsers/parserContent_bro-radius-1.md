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
json-bro-activity = {
  Vendor = Bro
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Fields = [
    """exabeam_host=([^@=]+@\s*)?({host}\S+)""",
    """"ts\\?"+:[\[\\]*"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})"""
    #""""ts\\?"+:\\?"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"uid\\?"+:\\?"+({conn_id}[^"]+)""",
    """"id\.orig_h\\?"+:\\?"+({src_ip}[a-fA-F\d.:]+)""",
    """"id\.orig_p\\?"+:({src_port}\d+)""",
    """"id\.resp_h\\?"+:\\?"+({dest_ip}[a-fA-F\d.:]+)""",
    """"id\.resp_p\\?"+:({dest_port}\d+)""",
    """"proto\\?"+:\\?"+({protocol}[^"]+)""",
  ]

```