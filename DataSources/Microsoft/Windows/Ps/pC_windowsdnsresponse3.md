#### Parser Content
```Java
{
Name = windows-dns-response-3
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "dns-response"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """ PACKET """, """ R U [""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """({time}\d{1,2}\/\d{1,2}\/\d{4} \d{1,2}:\d{1,2}:\d{1,2} (am|AM|pm|PM))\s{1,100}\S{1,2000}\s{1,100}PACKET\s""",
    """\sPACKET\s{1,100}\S{1,2000}\s{1,100}({protocol}\S{1,2000})\s{1,100}({activity}\S{1,2000})\s{1,100}({src_ip}[A-Fa-f\d:.]{1,2000})\s{1,100}\S{1,2000}\s{1,100}R U\s{1,100}\[\S{1,2000}\s{1,100}({response_flags}\S{1,2000})?\s{1,100}({dns_response_code}\S{1,2000})\]\s{1,100}({query_type}\S{1,2000})\s{1,100}({query}\S{1,2000}?)\s"""
  ]


}
```