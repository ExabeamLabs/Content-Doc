#### Parser Content
```Java
{
Name = json-microsoft-dns-query
  Vendor = Microsoft
  Product = Microsoft Windows DNSServer
  Lms = Direct
  DataType = "dns-query"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """<leaf>""", """Microsoft-Windows-DNSServer""", """"QNAME":"""", """"QTYPE":"""" ]
  Fields = [
    """\d\d:\d\d:\d\d ({host}[^\s]+)\sMicrosoft-Windows-DNSServer""",
    """"EventTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """"EventId":({event_code}\d{1,100})""",
    """"ExecutionProcessID":({pid}\d{1,100})""",
    """"XID":"({query_id}\d{1,100})""",
    """"ExecutionThreadID":({thread_id}\d{1,100})""",
    """"InterfaceIP":"(0\.0\.0\.0|({dest_ip}[a-fA-F\d:.]+))""",
    """"Source":"({src_ip}[a-fA-F\d:.]+)""",
    """"Port":"({src_port}\d{1,100})""",
    """"QNAME":"({query}[^",]+?(\.({top_query}\w+\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)))?)\.",""",
    """"QTYPE":"({query_type}[^"]+)""",
    """"Flags":"({query_flags}[^"]+)""",
    """"BufferSize":"({bytes}\d{1,100})""",
    """"Domain":"((?i)NT AUTHORITY|({domain}[^"]+))""",
    """"AccountName":"((?i)SYSTEM|({user}[^"]+))""",
    """"UserID":"({user_sid}[^"]+)""",
  ]
}
```