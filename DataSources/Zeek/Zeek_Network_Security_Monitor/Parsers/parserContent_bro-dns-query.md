#### Parser Content
```Java
{
Name = bro-dns-query
  Product = Zeek Network Security Monitor
  DataType = "dns-query"
  Conditions = [ """"id.orig_h""", """"id.resp_h""", """"_path":"dns_red"""", """"query":"""", """"qtype_name":"""" ]
  Fields = ${BroParserTemplates.json-bro-activity.Fields}[
    """"query":"({query}[^"]+)""",
    """"qtype_name":"({query_type}[^"]+)""",
  ]
}
json-bro-activity = {
  Vendor = Zeek
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Fields = [
    """exabeam_host=([^@=]+@\s{0,100})?({host}\S+)""",
    """"ts\\?"{1,20}:[\[\\]*"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})"""
    #""""ts\\?"{1,20}:\\?"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"uid\\?"{1,20}:\\?"{1,20}({conn_id}[^"]+)""",
    """"id\.orig_h\\?"{1,20}:\\?"{1,20}({src_ip}[a-fA-F\d.:]+)""",
    """"id\.orig_p\\?"{1,20}:({src_port}\d{1,100})""",
    """"id\.resp_h\\?"{1,20}:\\?"{1,20}({dest_ip}[a-fA-F\d.:]+)""",
    """"id\.resp_p\\?"{1,20}:({dest_port}\d{1,100})""",
    """"proto\\?"{1,20}:\\?"{1,20}({protocol}[^"]+)""",
  ]

```