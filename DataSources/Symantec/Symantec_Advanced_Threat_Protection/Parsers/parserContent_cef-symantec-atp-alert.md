#### Parser Content
```Java
{
Name = cef-symantec-atp-alert
  Vendor = Symantec
  Product = Symantec Advanced Threat Protection
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """|Symantec|Symantec Advanced Threat Protection|""", """"device_time":""" ]
  Fields = [
    """CEF:([^\|]*\|){5}({alert_name}[^\|]+)""",
    """"device_time":"({time}\d+\-\d+\-\d+T\d+:\d+:\d+\.\d+Z)""",
    """\Wdvchost=({host}.+?)(\s+\w+=|\s*$)""",
    """"device_name":"({src_host}[^"]+)"""",
    """"device_domain":"({domain}[^"]+)"""",
    """"file":\{.*?"md5":"?(?:null|({md5}[^"]+))"""",
    """"file":\{.*?"path":"({file_path}({file_parent}[^"]*?)({file_name}[^"\\\/]+?)(\.({file_ext}[^"\\\/.]+))?)"""",
    """"user_name":"(?:SYSTEM|(A|a)dministrator|({user_fullname}[^\s"]+\s+[^\s"]+)|({user}[^"]+))".+?\]""",
    """"device_os_name":"({os}[^"]+)"""",
    """"event_id":({alert_id}\d+)""",
    """"severity_id":({alert_severity}\d+)""",
    """"device_ip":"({src_ip}[^"]+)"""",
    """"status_detail":"({alert_type}[^"]+)"""",
    """"product_name":"({product_name}[^"]+)"""",
    """"message":"({additional_info}[^"]+)"""",
  ]
  DupFields = ["host->dest_host", "file_name->process_name"]
}
```