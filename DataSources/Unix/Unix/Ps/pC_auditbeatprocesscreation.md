#### Parser Content
```Java
{
Name = auditbeat-process-creation
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = ["""logstash-auditbeat""", """"process""""]
  Fields = [
    """"@timestamp":"({time}[^"]{1,2000})""",
    """"name_map":\{.*?"uid":"(|({user}[^"]{1,2000}))"""",
    """"actor":\{[^\}]{1,2000}?"secondary":"(|({user}[^"]{1,2000}))""""
    """"actor":\{[^\}]{1,2000}?"primary":"(|({account}[^"]{1,2000}))""""
    """"name_map":\{.*?"suid":"(|({account}[^"]{1,2000}))"""",
    """"user":\{.*?"uid":"({user_id}\d{1,100})"""",
    """"user":\{.*?"auid":"({account_used_id}\d{1,100})"""",
    """"user":\{.*?"gid":"({group_id}\d{1,100})"""",
    """"pid":"({pid}\d{1,100})""",
    """"ppid":"({parent_process_id}\d{1,100})""",
    """"process":\{.*?"name":"(|({process_name}[^"]{1,2000}))"""",
    """"process":\{.*?"exe":"(|({process}({process_directory}[^"]{1,2000}\/).*?))"""",
    """"process":\{.*?"args":\[({arg}[^\[\]]{1,2000}?)\]""",
    """"process":\{.*?"title":"({command_line}.*?)"(\}|,)"""
    """"host":\{.*?"name":"(|({host}[^"]{1,2000}))"""",
    """"result":"({outcome}[^"]{1,2000})"""",
    """"event":\{.*?"type":"(|({activity_type}[^"]{1,2000}))"""",
    """"event":\{.*?"action":"(|({log_type}[^"]{1,2000}))"""",
    """"event":\{.*?"category":"(|({sub_event_type}[^"]{1,2000}))"""",
    """"event":\{.*?"outcome":"(|({outcome}[^"]{1,2000}))"""",
    """"hostname":"({src_host}[^"]{1,2000})"""",
 ]
 DupFields = [ "process_directory->directory", "process->path", "host->dest_host", "pid->process_id" ]
}, 
 {
    Name = named-dns-query
    Vendor = Infoblox
    Product = BloxOne
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