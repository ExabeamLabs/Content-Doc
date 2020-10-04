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
{
  Name = cisco-ssh-login
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "ssh-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """%SSH-""", """SSH2_USERAUTH:""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s*)?({host}[\w.\-]+)""",
    """({event_code}%SSH-[^:]+)""",
    """SSH2_USERAUTH:\s*User '(|({user}[^']+))' authentication for SSH2 Session from ({src_ip}[A-Fa-f:\d.]+)""",
    """({outcome}Succeeded|Failed)""",
  ]
}
```