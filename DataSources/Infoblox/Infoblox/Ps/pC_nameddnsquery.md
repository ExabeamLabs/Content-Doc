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
      """exabeam_host=(::ffff:)?([^=]{1,2000}@\s{0,100})?({host}\S+)""",
      """\d\d:\d\d:\d\d (::ffff:)?({host}\S+)""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """({time}\d\d-\w+-\d\d\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
      """client\s{0,100}(::ffff:)?({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})#({src_port}\d{1,100})(?:)""",
      """query:\s{0,100}({query}[^\s]{1,2000}\.({top_query}\w+\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)))\s""",
      """query:\s{0,100}({query}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
      """\sIN\s({query_type}\w{1,5})\s""",
      """\s{1,100}IN\s.+?\s{1,100}({query_flags}[^\d\w].*?)\s""",
      """response:\s{0,100}({dns_response_code}[^\s]{1,2000})\s""",
      """IN\s{0,100}.+?s*(::ffff:)?({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """ CNAME ({cname}[^;]{1,2000}?)\.?;""",
    ]
  }
```