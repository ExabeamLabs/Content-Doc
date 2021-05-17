#### Parser Content
```Java
{
Name = syslog-sophos-snmp-alert-detected
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss a"
  Conditions = [ """ has been detected""", """SOPHOS:""", """SNMP Trap""", """Variable Bindings""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[^\s]{1,2000})""",
    """Address=({host}\S+)""",
    """({host}[\w\.-]{1,2000})\s{1,100}MSWinEventLog""",
    """\sReceived Time:({time}\d\d\d\d-\d\d-\d\d \d{1,2}:\d\d:\d\d (AM|PM|am|pm))""",
    """\sSource:({src_ip}[^\(\s]{1,2000})(\s{0,100}\(({src_host}[\w\.-]{1,2000})\))?""",
    """:=\s{0,100}({alert_type}.+?)\s{1,100}'({alert_name}.+?)'\s{1,100}has been detected in "({file_path}(({file_parent}.+)[\\\/])?({file_name}.+?))"\.(\s{1,100}({additional_info}.+?)\s{1,100}(\S+:=|$))?""",
    """:=\s{0,100}({additional_info}[^"]{1,2000}?)\s{1,100}"({file_path}(({file_parent}.+)[\\\/])?({file_name}.+?))"\s{1,100}of\s{1,100}controlled application\s{1,100}'({alert_name}.+?)'\s{0,100}\(of type\s{1,100}({alert_type}.+?)\)\s{1,100}has been detected\.""",
  ]
  DupFields = [ "file_path->malware_url" ]
}
```