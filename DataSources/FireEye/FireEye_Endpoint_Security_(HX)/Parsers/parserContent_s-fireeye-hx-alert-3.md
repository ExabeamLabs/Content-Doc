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
     """infection-name":\s{0,100}"({alert_name}[^"]{1,2000})""",
     """hostname":\s{0,100}"({host}[^"]{1,2000})""",
     """last_poll_ip":\s{0,100}"({src_ip}[\da-fA-F.:]{1,2000})""",
     """infection-type":\s{0,100}"({alert_type}[^"]{1,2000})""",
     """"alert_id":\s{0,100}({alert_id}\d{1,100})""",
     """"infection":\s{0,100}\{"confidence-level":\s{0,100}"({alert_severity}[^"]{1,2000})""",
     """applied-action":\s{0,100}"((?i)none|({action}[^"]{1,2000}))""",
     """infected-object":[^}]{1,2000}?file-path":\s{0,100}"({file_path}(({file_parent}[^"]{0,2000}?[\\\/]{1,2000})?({file_name}[^\\\/"]{1,2000}?(\.({file_ext}\w+))?)))"""",
     """"username":\s{0,100}"((?i)SYSTEM|({user}[^"]{1,2000}))""",
     """"domain":\s{0,100}"((?i)NT AUTHORITY|({domain}[^"]{1,2000}))""",
     """infected-object":[^}]{1,2000}?md5sum":\s{0,100}"({md5}[^"]{1,2000})""",
     """infected-object":[^}]{1,2000}?sha1sum":\s{0,100}"({sha1}[^"]{1,2000})""",
     """infected-object":[^}]{1,2000}?sha256sum":\s{0,100}"({sha256}[^"]{1,2000})""",
  ]
}
```