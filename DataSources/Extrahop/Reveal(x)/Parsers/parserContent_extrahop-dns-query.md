#### Parser Content
```Java
{
Name = extrahop-dns-query
  Vendor = Extrahop
  Product = Reveal(x)
  Lms = Direct
  DataType = "dns-query"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS-SS:SS"
  Conditions = ["""opcode":"QUERY""", """vendor":"ExtraHop""", """qname""", """qtype""" ]
  Fields = [
     """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}-\d{1,100}:\d{1,100})\s{0,100}({host}[^\s]+)""",
     """"proto":"({protocol}[^"]+)""",
     """"clientAddr":"({src_ip}[A-Fa-f:\d.]+)""",
     """"serverAddr":"({dest_ip}[A-Fa-f:\d.]+)""",
     """"clientPort":({src_port}\d{1,100})""",
     """"serverPort":({dest_port}\d{1,100})""",
     """"qname":"({query}[^"]+)""",
     """"qtype":"({query_type}[^"]+)""",
     """"error":"({error_code}[^"]+)""",
     """"rspBytes":({bytes}\d{1,100})""",
]
}
```