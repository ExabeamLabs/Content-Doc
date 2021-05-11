#### Parser Content
```Java
{
Name = redcanary-security-alert
  Vendor = Red Canary
  Product = Red Canary
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """, u'headline':""", """, u'subclassifications':""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """u'timestamp':\s{0,100}u'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """u'subclassifications':\s{0,100}\[u'({alert_type}[^'\]]+)""",
    """u'severity':\s{0,100}u'({alert_severity}[^'\]]+)""",
    """u'headline':\s{0,100}u'({alert_name}[^',]+)""",
    """u'url':\s{0,100}u'({malware_url}[^']+)""",
    """u'path':\s{0,100}u'({process}({directory}(?:[^']+)?[\\\/])?({process_name}[^\\\/']+))""",
    """u'md5':\s{0,100}u'({md5}[^']+)""",
    """u'username':\s{0,100}u'({user}[^'\s]+)""",
    """u'sensor_id':\s{0,100}u'({sensor_id}[^']+)""",
    """u'ip_addresses':\s{0,100}\[u'({src_ip}[A-Fa-f:\d.]+)""",
    """u'hostname':\s{0,100}u'({src_host}[^']+)""",
    """u'summary':\s{0,100}u'({additional_info}[^']+)""",
  ]
}
```