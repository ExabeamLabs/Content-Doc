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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\}\s+({src_ip}[^:]+):({src_port}\d+)\s+->\s+({dest_ip}[^:]+):({dest_port}\d+)"""
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""
    """\[Classification:\s+({alert_type}[^\]]+)""",
    """\[Priority:\s+({alert_severity}[^\]]+)""",
    """PROTOCOL-({protocol}[^\s]+)\s+({alert_name}.+?)\s*\[Classification:"""
  ]
}
```