#### Parser Content
```Java
{
Name = snort-network-alert-2
  Vendor = Snort
  Product = Snort
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """[Classification:""","""[Priority:""","""snort[""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\s({host}[^\s]+)\s+snort\["""
    """\}\s+({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:({src_port}\d+))?\s+->\s({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:({dest_port}\d+))?"""
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""
    """\[Classification:\s+({alert_type}[^\]]+)""",
    """\[Priority:\s+({alert_severity}[^\]]+)""",
    """\d+\]\s({alert_name}.+?)\s*\[Classification"""
    """snort\[({event_code}\d+)""",
    """\)\s({alert_name}.+?)\s*\[Classification""",
    """Priority:.+?\{(PROTO:)?({protocol}[^\}]+)\}"""
  ]
}
```