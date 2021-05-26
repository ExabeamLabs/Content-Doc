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
     """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}-\d{1,100}:\d{1,100})\s{0,100}({host}[^\s]{1,2000})""",
     """"proto":"({protocol}[^"]{1,2000})""",
     """"clientAddr":"({src_ip}[A-Fa-f:\d.]{1,2000})""",
     """"serverAddr":"({dest_ip}[A-Fa-f:\d.]{1,2000})""",
     """"clientPort":({src_port}\d{1,100})""",
     """"serverPort":({dest_port}\d{1,100})""",
     """"qname":"({query}[^"]{1,2000})""",
     """"qtype":"({query_type}[^"]{1,2000})""",
     """"error":"({error_code}[^"]{1,2000})""",
     """"rspBytes":({bytes}\d{1,100})""",
]
}
```