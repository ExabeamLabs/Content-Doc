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
```