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
    """"bytes":({bytes}\d+)""",
    """"dest_ip":"({dest_ip}[a-fA-F\d.:]+)""",
    """"dest_mac":"({dest_mac}[a-fA-F\d:]+)""",
    """"dest_port":({dest_port}\d+)""",
    """"src_ip":"({src_ip}[a-fA-F\d.:]+)""",
    """"src_mac":"({src_mac}[a-fA-F\d:]+)""",
    """"src_port":({src_port}\d+)""",
    """"time_taken":({time_taken}\d+)""",
    """"transport":"({protocol}[^"]+)""",
    """"ttl":\[({response_ttl}\d+)""",
    """"query":\["({query}[^"]+)""",
    """"query_type":\["({query_type}[^"]+)""",
    """"host_addr":\["({host}[^"]+)""",
    """"hostname":\["({host}[^"]+)"""
  ]
}
```