#### Parser Content
```Java
{
Name = redcanary-security-alert
  Vendor = Red Canary
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """, u'headline':""", """, u'subclassifications':""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """u'timestamp':\s*u'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """u'subclassifications':\s*\[u'({alert_type}[^'\]]+)""",
    """u'severity':\s*u'({alert_severity}[^'\]]+)""",
    """u'headline':\s*u'({alert_name}[^',]+)""",
    """u'url':\s*u'({malware_url}[^']+)""",
    """u'path':\s*u'({process}({directory}(?:[^']+)?[\\\/])?({process_name}[^\\\/']+))""",
    """u'md5':\s*u'({md5}[^']+)""",
    """u'username':\s*u'({user}[^'\s]+)""",
    """u'sensor_id':\s*u'({sensor_id}[^']+)""",
    """u'ip_addresses':\s*\[u'({src_ip}[A-Fa-f:\d.]+)""",
    """u'hostname':\s*u'({src_host}[^']+)""",
    """u'summary':\s*u'({additional_info}[^']+)""",
  ]
}
```