#### Parser Content
```Java
{
Name = q-cisco-dns-response
  Vendor = Cisco
  Product = Cisco Umbrella
  Lms = QRadar
  DataType = "dns-response"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """"MostGranularIdentity"""", """"Identities"""", """"QueryType"""", """"ResponseCode"""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"Timestamp"{0,20}:"{0,20}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """"Identities"{0,20}:"{0,20}({identities}[^"]{1,2000})""",
    """"InternalIp"{0,20}:"{0,20}({dest_ip}[^"]{1,2000})""",
    """"ExternalIp"{0,20}:"{0,20}({src_ip}[^"]{1,2000})""",
    """"Action"{0,20}:"{0,20}({outcome}[^"]{1,2000})""",
    """"QueryType"{0,20}:"{0,20}({query_type}[^"]{1,2000})""",
    """"ResponseCode"{0,20}:"{0,20}({dns_response_code}[^"]{1,2000})""",
    """"Domain"{0,20}:"{0,20}({query}[^"]{1,2000})""",
    """"Categories"{0,20}:"{0,20}({category}[^"]{1,2000})""",
  ]


}
```