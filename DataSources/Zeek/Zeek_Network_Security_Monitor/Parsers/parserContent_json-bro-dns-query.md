#### Parser Content
```Java
{
Name = json-bro-dns-query
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Direct
  DataType = "dns-query"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """/dns.log""", """"uid\":""", """"id.orig_h\":""", """"id.resp_h\":""", """"query\":""" ]
  Fields = [
    """"HOST"{1,20}:\s{0,100}"{1,20}({host}[^"]{1,2000})"""",
    """"TAGS"{1,20}:\s{0,100}"{1,20}({event_code}[^"]{1,2000})"""",
    """"ts\\?"{1,20}:\\?"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"id\.orig_h\\?"{1,20}:\\?"{1,20}({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"id\.orig_p\\?"{1,20}:({src_port}\d{1,100})""",
    """"id\.resp_h\\?"{1,20}:\\?"{1,20}({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """"id\.resp_p\\?"{1,20}:({dest_port}[a-fA-F\d.:]{1,2000})""",
    """"proto\\?"{1,20}:\\?"{1,20}({protocol}[^"\\]{1,2000})""",
    """"trans_id\\?"{1,20}:({query_id}\d{1,100})""",
    """"query\\?"{1,20}:\\?"{1,20}({query}[^"\\]{1,2000})""",
    """"qtype_name\\?"{1,20}:\\?"{1,20}({query_type}[^"\\]{1,2000})""",
    """"rejected\\?"{1,20}:({outcome}\w+)"""
  ]
}
```