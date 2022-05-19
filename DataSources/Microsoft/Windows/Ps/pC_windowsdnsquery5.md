#### Parser Content
```Java
{
Name = windows-dns-query-5
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "dns-query"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """ PACKET """, """   N [""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """({time}\d{1,2}\/\d{1,2}\/\d{4} \d{1,2}:\d{1,2}:\d{1,2} (am|AM|pm|PM))\s{1,100}\S{1,2000}\s{1,100}PACKET\s""",
    """\sPACKET\s{1,100}\S{1,2000}\s{1,100}({protocol}\S{1,2000})\s{1,100}({activity}\S{1,2000})\s{1,100}({src_ip}[A-Fa-f\d:.]{1,2000})\s{1,100}\S{1,2000}\s{1,100}N\s{1,100}\[\S{1,2000}\s{1,100}({query_flags}\S{1,2000})?\s{1,100}\S{1,2000}\]\s{1,100}({query_type}\S{1,2000})\s{1,100}({query}[^\s]{1,2000})\s"""
  ]


}
```