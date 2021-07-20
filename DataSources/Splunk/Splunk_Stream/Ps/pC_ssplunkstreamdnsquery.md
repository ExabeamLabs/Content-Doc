#### Parser Content
```Java
{
Name = s-splunkstream-dns-query
  Vendor = Splunk
  Product = Splunk Stream
  Lms = Splunk
  DataType = "dns-query"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """"query":""", """:dns"""", """"time_taken"""", """"message_type"""" ]
  Fields = [
    """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"bytes":({bytes}\d{1,100})""",
    """"dest_ip":"({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """"dest_mac":"({dest_mac}[a-fA-F\d:]{1,2000})""",
    """"dest_port":({dest_port}\d{1,100})""",
    """"src_ip":"({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"src_mac":"({src_mac}[a-fA-F\d:]{1,2000})""",
    """"src_port":({src_port}\d{1,100})""",
    """"time_taken":({time_taken}\d{1,100})""",
    """"transport":"({protocol}[^"]{1,2000})""",
    """"ttl":\[({response_ttl}\d{1,100})""",
    """"query":\["({query}[^"]{1,2000}\.({top_query}\w+\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)))""",
    """"query_type":\["({query_type}[^"]{1,2000})""",
    """"host_addr":\["({host}[^"]{1,2000})""",
    """"hostname":\["({host}[^"]{1,2000})"""
  ]
}
```