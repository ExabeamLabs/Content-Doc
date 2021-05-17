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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """u'timestamp':\s{0,100}u'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """u'subclassifications':\s{0,100}\[u'({alert_type}[^'\]]{1,2000})""",
    """u'severity':\s{0,100}u'({alert_severity}[^'\]]{1,2000})""",
    """u'headline':\s{0,100}u'({alert_name}[^',]{1,2000})""",
    """u'url':\s{0,100}u'({malware_url}[^']{1,2000})""",
    """u'path':\s{0,100}u'({process}({directory}(?:[^']{1,2000})?[\\\/])?({process_name}[^\\\/']{1,2000}))""",
    """u'md5':\s{0,100}u'({md5}[^']{1,2000})""",
    """u'username':\s{0,100}u'({user}[^'\s]{1,2000})""",
    """u'sensor_id':\s{0,100}u'({sensor_id}[^']{1,2000})""",
    """u'ip_addresses':\s{0,100}\[u'({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """u'hostname':\s{0,100}u'({src_host}[^']{1,2000})""",
    """u'summary':\s{0,100}u'({additional_info}[^']{1,2000})""",
  ]
}
```