#### Parser Content
```Java
{
Name = syslog-mcafee-network-alert
  Vendor = McAfee
  Product = McAfee NSM
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """ detected """, """ attack """, """(severity = """, """(result = """ ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d\d:\d\d),? ({host}[\w\-.]+)""",
    """detected ({direction}Inbound|Outbound|Bidirectional) attack ({alert_type}[^:\s]+?):? ({alert_name}.+?)\s*\(severity\s*=\s*(N\/A|({alert_severity}[^\)]+))\).+?(N\/A|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})):(N\/A|({src_port}\d+)) -> (N\/A|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})):(N\/A|({dest_port}\d+)) \(result\s*=\s*(n\/a|({outcome}[^\)]+))\)""",
  ]
}
```