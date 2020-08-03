#### Parser Content
```Java
{
Name = json-bro-dns-query
  Vendor = Bro
  Product = Bro
  Lms = Direct
  DataType = "dns-query"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """/dns.log""", """"uid\":""", """"id.orig_h\":""", """"id.resp_h\":""", """"query\":""" ]
  Fields = [
    """"HOST"+:\s*"+({host}[^"]+)"""",
    """"TAGS"+:\s*"+({event_code}[^"]+)"""",
    """"ts\\?"+:\\?"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"id\.orig_h\\?"+:\\?"+({src_ip}[a-fA-F\d.:]+)""",
    """"id\.orig_p\\?"+:({src_port}\d+)""",
    """"id\.resp_h\\?"+:\\?"+({dest_ip}[a-fA-F\d.:]+)""",
    """"id\.resp_p\\?"+:({dest_port}[a-fA-F\d.:]+)""",
    """"proto\\?"+:\\?"+({protocol}[^"\\]+)""",
    """"trans_id\\?"+:({query_id}\d+)""",
    """"query\\?"+:\\?"+({query}[^"\\]+)""",
    """"qtype_name\\?"+:\\?"+({query_type}[^"\\]+)""",
    """"rejected\\?"+:({outcome}\w+)"""
  ]
}
```