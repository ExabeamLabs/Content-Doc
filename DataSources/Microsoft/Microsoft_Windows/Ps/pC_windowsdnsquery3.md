#### Parser Content
```Java
{
Name = windows-dns-query-3
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "dns-query"
  IsHVF = true
  TimeFormat = "dd.MM.yyyy HH.mm.ss"
  Conditions = [ """ PACKET """, """   Q [""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """({time}\d{1,100}\/\d{1,100}\/\d\d\d\d \d{1,2}:\d{1,2}:\d{1,2})\s{1,100}\S+\s{1,100}PACKET\s""",
    """({time}\d{1,2}.\d{1,2}\.\d{1,4} \d{1,2}\.\d{1,2}\.\d{1,2})\s\w+\sPACKET\s""",
    """\sPACKET\s{1,100}\S{1,2000}\s{1,100}({protocol}\S{1,2000})\s{1,100}({activity}\S{1,2000})\s{1,100}({src_ip}[a-fA-F\d.:]{1,2000})\s{1,100}\S{1,2000}\s{1,100}Q\s{1,100}\[\S{1,2000}\s{1,100}(\s|({query_flags}[^\s]{1,2000}))\s{1,100}\S{1,2000}\]\s{1,100}({query_type}\S{1,2000})\s{1,100}({query}[^",\s]{1,2000})"{0,20}"""
  ]


}
```