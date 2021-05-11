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
      """"collector_name":"({host}[^"]+)"""",
      """\Wrt=({time}\d{1,100})""",
      """"feature_name":"({alert_name}[^"]+)"""",
      """"severity_id":({alert_severity}\d{1,100})""",
      """\Wdst=({dest_ip}[a-fA-F\d.:]+)""",
      """\Wdvchost=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
      """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
      """\Wshost=({src_host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
      """"user_name":"({user}[^"]+)"""",
      """"type":"({alert_type}[^"]+)"""",
      """"device_domain":"({domain}[^"]+)"""",
      """"src_ip":"({src_ip}[^"]+)"""",
      """"src_port":"({src_port}\d{1,100})""",
      """"dst_port":"({dest_port}\d{1,100})""",
      """"src_name":"({src_host}[^"]+)"""",
      """"dst_ip":"({dest_ip}[^"]+)"""",
      """"device_os_name":"({os}[^"]+)"""",
      """"product_name":"({product_name}[^"]+)"""",
    ]
  }
```