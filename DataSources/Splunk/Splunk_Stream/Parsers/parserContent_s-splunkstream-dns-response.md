#### Parser Content
```Java
{
Name = s-splunkstream-dns-response
  Vendor = Splunk
  Product = Splunk Stream
  Lms = Splunk
  DataType = "dns-response"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """"reply_code":""", """:dns"""", """"time_taken"""", """"message_type"""" ]
  Fields = [
    """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"bytes":({bytes}\d{1,100})""",
    """"dest_ip":"({dest_ip}[a-fA-F\d.:]+)""",
    """"dest_mac":"({dest_mac}[a-fA-F\d:]+)""",
    """"dest_port":({dest_port}\d{1,100})""",
    """"src_ip":"({src_ip}[a-fA-F\d.:]+)""",
    """"src_mac":"({src_mac}[a-fA-F\d:]+)""",
    """"src_port":({src_port}\d{1,100})""",
    """"time_taken":({time_taken}\d{1,100})""",
    """"transport":"({protocol}[^"]+)""",
    """"ttl":\[({response_ttl}\d{1,100})""",
    """"query":\["({query}[^"]+)""",
    """"query_type":\["({query_type}[^"]+)""",
    """"reply_code":"({dns_response_code}[^"]+)""",
    """"host_addr":\["({host}[^"]+)""",
    """"hostname":\["({host}[^"]+)"""
  ]
}
```