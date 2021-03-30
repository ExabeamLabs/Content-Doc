#### Parser Content
```Java
{
Name = s-stealthwatch-network-alert-1
  Vendor = Cisco
  Product = Cisco StealthWatch (Lancope)
  Lms = Splunk
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """ StealthWatch[""", """<custom_condition_cont-7162>""" ]
  Fields = [
    """\w+\s+\d+\s+\d+:\d+:\d+\s+({host}[\w\-.]+)\s+StealthWatch\[\d+\]:\s*({time}\d+-\d+-\d+T\d+:\d+:\d+Z)\s*.*?({alert_name}[A-Z].+?)\.?\s*\d*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*?\s*({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+.*?({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*\S*\s+(({bytes_num}[\d\.]+)\s*({bytes_unit}\w+)\s+bytes)?""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```