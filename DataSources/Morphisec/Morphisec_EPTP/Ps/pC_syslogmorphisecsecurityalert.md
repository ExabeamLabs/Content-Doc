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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d ({host}[\w.\-]{1,2000}) Morphisec""",
    """"Protector IP":\["({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"Message":\["({additional_info}[^"]{1,2000})"""",
    """({alert_name}attack)""",
    """"Logged In UserName":\["(({domain}[^\\\/"]{1,2000})[\\\/])?({user}[^\\\/"]{1,2000})"""",
    """"Attacked Module":\["({malware_url}[^"]{1,2000})"""",
    """"Attack Time":\["({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """"Computer Name":\["({src_host}[^"]{1,2000})"""",
  ]
  DupFields = ["alert_name->alert_type"]
}
```