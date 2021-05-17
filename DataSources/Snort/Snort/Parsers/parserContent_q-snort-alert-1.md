#### Parser Content
```Java
{
Name = q-snort-alert-1
  Vendor = Snort
  Product = Snort
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """[Classification:""","""[Priority:""","""PROTOCOL-""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\}\s{1,100}({src_ip}[^:]{1,2000}):({src_port}\d{1,100})\s{1,100}->\s{1,100}({dest_ip}[^:]{1,2000}):({dest_port}\d{1,100})"""
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""
    """\[Classification:\s{1,100}({alert_type}[^\]]{1,2000})""",
    """\[Priority:\s{1,100}({alert_severity}[^\]]{1,2000})""",
    """PROTOCOL-({protocol}[^\s]{1,2000})\s{1,100}({alert_name}.+?)\s{0,100}\[Classification:"""
  ]
}
```