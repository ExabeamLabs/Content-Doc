#### Parser Content
```Java
{
Name = cisco-dns-response-2
  Vendor = Cisco
  Product = Umbrella
  Lms = Direct
  DataType = "dns-response"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """,EventType":"""", """,Identities":"""", """,ResponseCode":"""", """,BlockedCategories":"""",""",QueryType":"""" ]
  Fields = [
    """,Timestamp":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),""",
    """,Identities":"({identities}[^,]{1,2000}),""",
    """,InternalIp":"({dest_ip}[a-fA-F\d:\.]{1,2000}),""",
    """,ExternalIp":"({src_ip}[a-fA-F\d:\.]{1,2000}),""",
    """,Action":"({outcome}[^,]{1,2000}),""",
    """,QueryType":"({query_type}[^,]{1,2000}),""",
    """,ResponseCode":"({dns_response_code}[^,]{1,2000}),""",
    """,Domain":"({query}[^,]{1,2000}),""",
    """,Categories":"({categories}({category}[^,"]{1,2000})[^"]{0,2000}),"""
  ]


}
```