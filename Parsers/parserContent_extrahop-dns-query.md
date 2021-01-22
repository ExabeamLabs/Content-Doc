#### Parser Content
```Java
{
Name = extrahop-dns-query
  Vendor = Extrahop
  Product = Extrahop
  Lms = Direct
  DataType = "dns-query"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS-SS:SS"
  Conditions = ["""opcode":"QUERY""", """vendor":"ExtraHop""", """qname""", """qtype""" ]
  Fields = [
     """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+-\d+:\d+)\s*({host}[^\s]+)""",
     """"proto":"({protocol}[^"]+)""",
     """"clientAddr":"({src_ip}[A-Fa-f:\d.]+)""",
     """"serverAddr":"({dest_ip}[A-Fa-f:\d.]+)""",
     """"clientPort":({src_port}\d+)""",
     """"serverPort":({dest_port}\d+)""",
     """"qname":"({query}[^"]+)""",
     """"qtype":"({query_type}[^"]+)""",
     """"error":"({error_code}[^"]+)""",
     """"rspBytes":({bytes}\d+)""",
]
}
```