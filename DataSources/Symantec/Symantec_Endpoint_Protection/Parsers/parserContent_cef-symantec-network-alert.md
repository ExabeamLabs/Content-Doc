#### Parser Content
```Java
{
Name = cef-symantec-network-alert
    Vendor = Symantec
    Product = Symantec Endpoint Protection
    Lms = ArcSight
    DataType = "network-alert"
    TimeFormat = "epoch"
    Conditions = [ """CEF""", """|Symantec|Symantec Endpoint Protection|""" ]
    Fields = [
      """"collector_name":"({host}[^"]{1,2000})"""",
      """\Wrt=({time}\d{1,100})""",
      """"feature_name":"({alert_name}[^"]{1,2000})"""",
      """"severity_id":({alert_severity}\d{1,100})""",
      """\Wdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
      """\Wdvchost=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
      """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
      """\Wshost=({src_host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
      """"user_name":"({user}[^"]{1,2000})"""",
      """"type":"({alert_type}[^"]{1,2000})"""",
      """"device_domain":"({domain}[^"]{1,2000})"""",
      """"src_ip":"({src_ip}[^"]{1,2000})"""",
      """"src_port":"({src_port}\d{1,100})""",
      """"dst_port":"({dest_port}\d{1,100})""",
      """"src_name":"({src_host}[^"]{1,2000})"""",
      """"dst_ip":"({dest_ip}[^"]{1,2000})"""",
      """"device_os_name":"({os}[^"]{1,2000})"""",
      """"product_name":"({product_name}[^"]{1,2000})"""",
    ]
  }
```