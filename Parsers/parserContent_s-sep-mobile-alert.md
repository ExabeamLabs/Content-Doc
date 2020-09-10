#### Parser Content
```Java
{
Name = s-sep-mobile-alert
    Vendor = Symantec
    Product = Symantec Endpoint Protection Mobile
    Lms = Splunk
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [ """"type": "Malware"""" , """current_risk_warnings""", """package_name""" ]
    Fields = [
      """exabeam_host=({host}[^\s]+)""",
      """"timestamp":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+[^"]+)""",
      """"email":\s*"({user_email}[^"]+)",\s*"name":\s*"({user_fullname}[^"]+)"""",
      """"product_name":\s*"({product_name}[^"]+)""",
      """"os_type":\s*"({os}[^"]+)""",
      """"device":[^}]+?"name":\s*"({src_host}[^"]+)"""",
      """"sub_type":\s*"({alert_type}[^"]+)""",
      """"event_type":\s*"({additional_info}[^"]+)""",
      """"severity":\s*"({alert_severity}[^"]+)",\s*"id":\s*({alert_id}\d+)""",
      """"package_name":\s*"({alert_name}[^"]+)""",
      """"apk_hash":\s*"({md5}[^"]+)""",
    ]
  }
  
{
  Name = symantec-atp-alert
  Vendor = Symantec
  Product = Symantec Advanced Threat Protection
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """|Symantec|ATPU|""", """|atp_incident|""", """"events":""" ]
  Fields = [
    """\Wdevice_time=({time}\d+\-\d+\-\d+T\d+:\d+:\d+\.\d+Z)""",
    """"device_name":"({host}[^"]+)"""",
    """"events":\[.+?"signature_name":"({alert_name}[^"]+)".+?\]""",
    """"events":\[.+?"threat":\{.*?"name":"({alert_name}[^"]+)".*?\}.+?\]""",
    """"rule_name":"({alert_type}[^"]+)"""",
    """"events":\[.+?"alert":"({alert_type}[^"]+)".+?\]""",
    """"events":\[.+?"file":\{.*?"md5":"?(?:null|({md5}[^"]+))"?.*?\}.+?\]""",
    """"events":\[.+?"file":\{.*?"folder":"({file_parent}[^"]+)".*?\}.+?\]""",
    """"events":\[.+?"file":\{.*?"name":"({file_name}[^"]+)".*?\}.+?\]""",
    """"events":\[.+?"email_subject":"({additional_info}[^"]+)".+?\]""",
    """"events":\[.+?"incident_priority_level":"({alert_severity}[^"]+)".+?\]""",
    """"events":\[.+?"user_name":"(?:SYSTEM|(A|a)dministrator|({user_fullname}[^\s"]+\s+[^\s"]+)|({user}[^"]+))".+?\]""",
    """"events":\[.+?"sender":\{.*?"email_address":"({user_email}[^"]+)".*?\}.+?\]""",
    """"events":\[.+?"device_name":"({src_host}[^"]+)".+?\]""",
    """"events":\[.+?"device_ip":"({src_ip}[^"]+)".+?\]""",
    """"events":\[.+?"email_action":"({outcome}[^"]+)".+?\]""",
    """"events":\[.+?"actual_action":"({outcome}[^"]+)".+?\]""",
    """"events":\[.+?"time":"({time}\d+\-\d+\-\d+T\d+:\d+:\d+\.\d+Z)".+?\]""",
    """"atp_incident_id":({alert_id}\d+)"""
  ]
  DupFields = ["host->dest_host", "file_name->process_name"]
}
```