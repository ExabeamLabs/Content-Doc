#### Parser Content
```Java
{
Name = infoblox-nios-dns-query
  Vendor = Infoblox
  Product = NIOS
  Lms = Direct
  DataType = "dns-query"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = ["""infoblox""", """"hostname":""", """"client_ip\":""", """"query_type\":""", """"query_name\":""" ]
  Fields = [
     """hostname":"({host}[\w.-]{1,2000})"""",
     """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
     """"client_ip\\":\\"({src_ip}[a-fA-F\d.:]{1,2000})\\"""",
     """"query_type\\":\\"({query_type}[^"]{1,2000}?)\\"""",
     """"query_name\\":\\"({query}[^"]{1,2000}?)\\"""",
  ]


}
```