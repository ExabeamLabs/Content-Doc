#### Parser Content
```Java
{
Name = bind-dns-query-3
  Vendor = BIND
  Product = BIND
  Lms = Direct
  DataType = "dns-query"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """[][]""", """<CLIENT_DATA>:""", """ query: """ ]
  Fields = [
    """<\d{1,100}>\d{1,100} ({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\+|\-)\d\d:\d\d) ({host}[\w.\-]{1,2000})""",
    """({src_ip}[a-fA-F\d.:]{1,2000})\#({src_port}\d{1,100}):\s{1,100}query:\s{1,100}({query}.+?)\s{1,100}IN\s{1,100}({query_type}\S+)""",
  ]
}
```