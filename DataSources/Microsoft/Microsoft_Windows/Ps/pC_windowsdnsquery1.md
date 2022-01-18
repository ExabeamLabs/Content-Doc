#### Parser Content
```Java
{
Name = windows-dns-query-1
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "dns-query"
  IsHVF = true
  TimeFormat = "M/d/yyyy H:mm:ss a"
  Conditions = [ """ PACKET """, """   Q [""", """M """ ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """({time}\d{1,100}\/\d{1,100}\/\d\d\d\d \d{1,2}:\d{1,2}:\d{1,2}((\+|\-)\d\d:\d\d)? (am|AM|pm|PM))\s{1,100}\S+\s{1,100}PACKET\s{1,100}\S+\s{1,100}({protocol}\S+)\s{1,100}({activity}\S+)\s{1,100}({src_ip}[a-fA-F\d.:]{1,2000})\s{1,100}\S+\s{1,100}Q\s{1,100}\[\S+\s{1,100}(\s|({query_flags}.+?))\s{1,100}\S+\]\s{1,100}({query_type}\S+)\s{1,100}({query}.+?)\s""",
    """<Identifier>\S+\s{1,100}({host}\S+?)<\/Identifier>"""
  ]


}
```