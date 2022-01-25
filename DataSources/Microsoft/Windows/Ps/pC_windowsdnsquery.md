#### Parser Content
```Java
{
Name = windows-dns-query
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "dns-query"
  IsHVF = true
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """UDP question info at """, """Buf length =""" ]
  Fields = [
    """exabeam_host=({host}[^\s]{0,2000})""",
    """({time}\d{1,100}\/\d{1,100}\/\d\d\d\d \d{1,100}:\d{1,100}:\d{1,100} (AM|am|PM|pm))""",
    """({protocol}UDP)\s{1,100}({activity}Rcv)\s{1,100}({src_ip}[a-fA-F\d.:]{1,2000})""",
    """Remote addr\s{0,100}({src_ip}[a-fA-F\d.:]{1,2000}),\s{0,100}port\s{0,100}({src_port}\d{1,100})""",
    """XID\s{1,100}0x({query_id}[\da-fA-F]{1,2000})""",
    """QTYPE\s{1,100}({query_type}\w+)""",
    """RCODE\s{1,100}[^(]{0,2000}?\(({result}[^(]{1,2000})\)""",
    """QUESTION SECTION:.*?Name\s{1,100}"({query}[^"]{1,2000})"""",
    """Buf length\s{0,100}=\s{0,100}\S+\s{0,100}\(({bytes}\d{1,100})""",
    """ANSWER SECTION:(\s{0,100}empty|.+?DATA\s{1,100}({response}\S+))"""
  ]


}
```