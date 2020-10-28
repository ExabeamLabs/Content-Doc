#### Parser Content
```Java
{
Name = named-dns-query
    Vendor = Infoblox
    Product = Infoblox
    Lms = Direct
    DataType = "dns-query"
    IsHVF = true
    TimeFormat = "dd-MMM-yyyy HH:mm:ss.SSS"
    Conditions = [ """: query: """, """named[""" ]
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}\S+)""",
      """\w+\s\d+\s\d+:\d+:\d+\s+(::ffff:)?({host}[\w\-.]+)""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """({time}\d\d-\w+-\d\d\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
      """client\s*({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})#({src_port}\d+)(?:)""",
      """query:\s*({query}[^\s]+\.({top_query}\w+\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)))\s""",
      """query:\s*({query}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
      """\sIN\s({query_type}\w{1,5})\s""",
      """\s+IN\s.+?\s+({query_flags}[^\d\w].*?)\s""",
      """response:\s*({dns_response_code}[^\s]+)\s""",
      """IN\s*.+?s*({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """ CNAME ({cname}[^;]+?)\.?;""",
    ]
  }
```