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
    """<\d+>\d+ ({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\+|\-)\d\d:\d\d) ({host}[\w.\-]+)""",
    """({src_ip}[a-fA-F\d.:]+)\#({src_port}\d+):\s+query:\s+({query}.+?)\s+IN\s+({query_type}\S+)""",
  ]
}
```