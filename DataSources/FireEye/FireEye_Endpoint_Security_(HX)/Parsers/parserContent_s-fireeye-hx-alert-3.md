#### Parser Content
```Java
{
Name = s-fireeye-hx-alert-3
  Vendor = FireEye
  Product = FireEye Endpoint Security (HX)
  Lms = Splunk
  DataType = "security-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"hostname":""", """"event_at":""", """"infection-name":""", """"detections":""", """"infected-object":""" ]  
  Fields = [
     """event_at":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
     """infection-name":\s*"({alert_name}[^"]+)""",
     """hostname":\s*"({host}[^"]+)""",
     """last_poll_ip":\s*"({src_ip}[\da-fA-F.:]+)""",
     """infection-type":\s*"({alert_type}[^"]+)""",
     """"alert_id":\s*({alert_id}\d+)""",
     """"infection":\s*\{"confidence-level":\s*"({alert_severity}[^"]+)""",
     """applied-action":\s*"((?i)none|({action}[^"]+))""",
     """infected-object":[^}]+?file-path":\s*"({file_path}(({file_parent}[^"]*?[\\\/]+)?({file_name}[^\\\/"]+?(\.({file_ext}\w+))?)))"""",
     """"username":\s*"((?i)SYSTEM|({user}[^"]+))""",
     """"domain":\s*"((?i)NT AUTHORITY|({domain}[^"]+))""",
     """infected-object":[^}]+?md5sum":\s*"({md5}[^"]+)""",
     """infected-object":[^}]+?sha1sum":\s*"({sha1}[^"]+)""",
     """infected-object":[^}]+?sha256sum":\s*"({sha256}[^"]+)""",
  ]
}
```