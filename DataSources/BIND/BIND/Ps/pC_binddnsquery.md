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
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
      """({time}\d\d-\w+-\d\d\d\d \d\d:\d\d:\d\d\.\d\d\d) info: client ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})#({src_port}\d{1,100})\s{1,100}\((|({query}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|([^\(\)]{1,2000}))).*?\):\s{0,100}query:\s{0,100}({=query}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|([^\s]{1,2000})).*?\s{1,100}IN ({query_type}[^\s]{1,2000})\s{1,100}({query_flags}.+?)\s{0,100}\(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """query:\s{0,100}({query}[^\s]{1,2000})"""
    ]
  

}
```