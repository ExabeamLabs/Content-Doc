#### Parser Content
```Java
{
Name = bind-dns-query
    Vendor = BIND
    Product = BIND
    Lms = Direct
    DataType = "dns-query"
    IsHVF = true
    TimeFormat = "dd-MMM-yyyy HH:mm:ss.SSS"
    Conditions = [ """ query: """, """ info: client """ ]
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}\S+)""",
      """({time}\d\d-\w+-\d\d\d\d \d\d:\d\d:\d\d\.\d\d\d) info: client ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})#({src_port}\d+)\s+\((|({query}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|([^\(\)]+))).*?\):\s*query:\s*({=query}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|([^\s]+)).*?\s+IN ({query_type}[^\s]+)\s+({query_flags}.+?)\s*\(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    ]
  }
```