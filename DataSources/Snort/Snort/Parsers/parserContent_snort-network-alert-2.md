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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """\s({host}[^\s]+)\s{1,100}snort\["""
    """\}\s{1,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:({src_port}\d{1,100}))?\s{1,100}->\s({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:({dest_port}\d{1,100}))?"""
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""
    """\[Classification:\s{1,100}({alert_type}[^\]]+)""",
    """\[Priority:\s{1,100}({alert_severity}[^\]]+)""",
    """\d{1,100}\]\s({alert_name}.+?)\s{0,100}\[Classification"""
    """snort\[({event_code}\d{1,100})""",
    """\)\s({alert_name}.+?)\s{0,100}\[Classification""",
    """Priority:.+?\{(PROTO:)?({protocol}[^\}]+)\}"""
  ]
}
```