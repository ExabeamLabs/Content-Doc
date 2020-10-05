#### Parser Content
```Java
{
Name = syslog-morphisec-security-alert
  Vendor = Morphisec
  Product = Morphisec EPTP
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """"Protector IP":["""",""""Attack Time":["""",""""Attacked Module":[""""]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d ({host}[\w.\-]+) Morphisec""",
    """"Protector IP":\["({src_ip}[a-fA-F\d.:]+)""",
    """"Message":\["({additional_info}[^"]+)"""",
    """({alert_name}attack)""",
    """"Logged In UserName":\["(({domain}[^\\\/"]+)[\\\/])?({user}[^\\\/"]+)"""",
    """"Attacked Module":\["({malware_url}[^"]+)"""",
    """"Attack Time":\["({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """"Computer Name":\["({src_host}[^"]+)"""",
  ]
  DupFields = ["alert_name->alert_type"]
}
```