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
      """\d\d:\d\d:\d\d ({host}\S+)""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """({time}\d\d-\w+-\d\d\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
      """client\s*({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})#({src_port}\d+)(?:)""",
      """query:\s*({query}[^\s]+)\s""",
      """query:\s*({query}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
      """\sIN\s({query_type}\w{1,5})\s""",
      """\s+IN\s.+?\s+({query_flags}[^\d\w].*?)\s""",
      """response:\s*({dns_response_code}[^\s]+)\s""",
      """IN\s*.+?s*({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """ CNAME ({cname}[^;]+?)\.?;""",
    ]
  }
```