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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"Timestamp"*:"*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """"Identities"*:"*({identities}[^"]+)""",
    """"InternalIp"*:"*({dest_ip}[^"]+)""",
    """"ExternalIp"*:"*({src_ip}[^"]+)""",
    """"Action"*:"*({outcome}[^"]+)""",
    """"QueryType"*:"*({query_type}[^"]+)""",
    """"ResponseCode"*:"*({dns_response_code}[^"]+)""",
    """"Domain"*:"*({query}[^"]+)""",
    """"Categories"*:"*({category}[^"]+)""",
  ]
}
```