#### Parser Content
```Java
{
Name = bind-dns-query-2
  Vendor = BIND
  Product = BIND
  Lms = Direct
  DataType = "dns-query"
  IsHVF = true
  TimeFormat = "dd-MMM-yyyy HH:mm:ss.SSS"
  Conditions = [ """ query: """, """ info: client """, """ named[""", """queries:""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d\d-\w+-\d\d\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
    """client\s*({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\#({src_port}\d+)""",
    """query:\s*({query}[^\s]+\.({top_query}\w+\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)))\s""",
    """query:\s*({query}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
    """\sIN\s({query_type}[^\s]+)\s+({query_flags}[^"\s]+)""",
  ]
}
```