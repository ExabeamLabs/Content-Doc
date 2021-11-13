#### Parser Content
```Java
{
Name = corelight-dns-query
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = ArcSight
  DataType = "dns-query"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """"id.orig_h":""", """"id.resp_h":""", """"dns",""", """"qtype_name":""" ]
  Fields = [
    """exabeam_host=([^@=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"_system_name":"({host}[^"]{1,2000})""",
    """"ts":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"id\.orig_h":"({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"id\.orig_p":({src_port}\d{1,100})""",
    """"id\.resp_h":"({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """"id\.resp_p":({dest_port}[a-fA-F\d.:]{1,2000})""",
    """"proto":"({protocol}[^"]{1,2000})""",
    """"query":"({query}[^"]{1,2000})"""",
    """"qtype_name":"({query_type}[^"]{1,2000})""",
  ]


}
```