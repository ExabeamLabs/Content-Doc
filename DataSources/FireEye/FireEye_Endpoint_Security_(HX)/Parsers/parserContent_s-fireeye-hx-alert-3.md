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
     """event_at":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
     """infection-name":\s{0,100}"({alert_name}[^"]+)""",
     """hostname":\s{0,100}"({host}[^"]+)""",
     """last_poll_ip":\s{0,100}"({src_ip}[\da-fA-F.:]+)""",
     """infection-type":\s{0,100}"({alert_type}[^"]+)""",
     """"alert_id":\s{0,100}({alert_id}\d{1,100})""",
     """"infection":\s{0,100}\{"confidence-level":\s{0,100}"({alert_severity}[^"]+)""",
     """applied-action":\s{0,100}"((?i)none|({action}[^"]+))""",
     """infected-object":[^}]+?file-path":\s{0,100}"({file_path}(({file_parent}[^"]*?[\\\/]+)?({file_name}[^\\\/"]+?(\.({file_ext}\w+))?)))"""",
     """"username":\s{0,100}"((?i)SYSTEM|({user}[^"]+))""",
     """"domain":\s{0,100}"((?i)NT AUTHORITY|({domain}[^"]+))""",
     """infected-object":[^}]+?md5sum":\s{0,100}"({md5}[^"]+)""",
     """infected-object":[^}]+?sha1sum":\s{0,100}"({sha1}[^"]+)""",
     """infected-object":[^}]+?sha256sum":\s{0,100}"({sha256}[^"]+)""",
  ]
}
```