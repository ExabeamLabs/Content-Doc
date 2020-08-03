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
      """\Wrt=({time}\d+)""",
      """"feature_name":"({alert_name}[^"]+)"""",
      """"severity_id":({alert_severity}\d+)""",
      """\Wdst=({dest_ip}[a-fA-F\d.:]+)""",
      """\Wdvchost=({host}.+?)(\s+\w+=|\s*$)""",
      """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
      """\Wshost=({src_host}.+?)(\s+\w+=|\s*$)""",
      """"user_name":"({user}[^"]+)"""",
      """"type":"({alert_type}[^"]+)"""",
      """"device_domain":"({domain}[^"]+)"""",
      """"src_ip":"({src_ip}[^"]+)"""",
      """"src_port":"({src_port}\d+)""",
      """"dst_port":"({dest_port}\d+)""",
      """"src_name":"({src_host}[^"]+)"""",
      """"dst_ip":"({dest_ip}[^"]+)"""",
      """"device_os_name":"({os}[^"]+)"""",
      """"product_name":"({product_name}[^"]+)"""",
    ]
  }
```