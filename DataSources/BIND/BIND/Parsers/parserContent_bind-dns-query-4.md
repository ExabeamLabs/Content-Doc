#### Parser Content
```Java
{
Name = bind-dns-query-4
  Vendor = BIND
  Product = BIND
  Lms = Direct
  DataType = "dns-query"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """: rpz """, """]: client """, """ named[""", """ rewrite """, """.rpz.""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d ({host}\S+) named""",
    """client\s[^\s]+?\s({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\#({src_port}\d+)\s\(({query}[^)]+)""",
    """rpz ({triggers}[^\s]+)\s({action}[^\s]+)\s""",
    """({event_name}rewrite)""",
      ]
}
```