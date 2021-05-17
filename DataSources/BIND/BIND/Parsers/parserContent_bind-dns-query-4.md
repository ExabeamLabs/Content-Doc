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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d ({host}\S+) named""",
    """client\s[^\s]{1,2000}?\s({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\#({src_port}\d{1,100})\s\(({query}[^)]{1,2000})""",
    """rpz ({triggers}[^\s]{1,2000})\s({action}[^\s]{1,2000})\s""",
    """({event_name}rewrite)""",
      ]
}
```