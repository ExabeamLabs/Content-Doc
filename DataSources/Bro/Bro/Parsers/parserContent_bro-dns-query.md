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