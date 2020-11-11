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
  Conditions = [ """PACKET""", """   Q [""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
    """({time}\d+\/\d+\/\d\d\d\d \d{1,2}:\d{1,2}:\d{1,2}((\+|\-)\d\d:\d\d)? (am|AM|pm|PM))\s+\S+\s+PACKET\s+\S+\s+({protocol}\S+)\s+({activity}\S+)\s+({src_ip}[a-fA-F\d.:]+)\s+\S+\s+Q\s+\[\S+\s+(\s|({query_flags}.+?))\s+\S+\]\s+({query_type}\S+)\s+({query}.+?)\s""",
    """<Identifier>\S+\s+({host}\S+?)<\/Identifier>"""
  ]
}
```