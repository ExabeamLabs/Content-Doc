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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"Timestamp"{0,20}:"{0,20}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """"Identities"{0,20}:"{0,20}({identities}[^"]+)""",
    """"InternalIp"{0,20}:"{0,20}({dest_ip}[^"]+)""",
    """"ExternalIp"{0,20}:"{0,20}({src_ip}[^"]+)""",
    """"Action"{0,20}:"{0,20}({outcome}[^"]+)""",
    """"QueryType"{0,20}:"{0,20}({query_type}[^"]+)""",
    """"ResponseCode"{0,20}:"{0,20}({dns_response_code}[^"]+)""",
    """"Domain"{0,20}:"{0,20}({query}[^"]+)""",
    """"Categories"{0,20}:"{0,20}({category}[^"]+)""",
  ]
}
```