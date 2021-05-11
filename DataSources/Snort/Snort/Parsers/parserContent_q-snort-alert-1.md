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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """\}\s{1,100}({src_ip}[^:]+):({src_port}\d{1,100})\s{1,100}->\s{1,100}({dest_ip}[^:]+):({dest_port}\d{1,100})"""
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""
    """\[Classification:\s{1,100}({alert_type}[^\]]+)""",
    """\[Priority:\s{1,100}({alert_severity}[^\]]+)""",
    """PROTOCOL-({protocol}[^\s]+)\s{1,100}({alert_name}.+?)\s{0,100}\[Classification:"""
  ]
}
```