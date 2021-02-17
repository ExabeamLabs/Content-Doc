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
    """exabeam_host=([^=]+?@\s*)?({host}[^\s]+)""",
    """Address=({host}\S+)""",
    """({host}[\w\.-]+)\s+MSWinEventLog""",
    """\sReceived Time:({time}\d\d\d\d-\d\d-\d\d \d{1,2}:\d\d:\d\d (AM|PM|am|pm))""",
    """\sSource:({src_ip}[^\(\s]+)(\s*\(({src_host}[\w\.-]+)\))?""",
    """:=\s*({alert_type}.+?)\s+'({alert_name}.+?)'\s+has been detected in "({file_path}(({file_parent}.+)[\\\/])?({file_name}.+?))"\.(\s+({additional_info}.+?)\s+(\S+:=|$))?""",
    """:=\s*({additional_info}[^"]+?)\s+"({file_path}(({file_parent}.+)[\\\/])?({file_name}.+?))"\s+of\s+controlled application\s+'({alert_name}.+?)'\s*\(of type\s+({alert_type}.+?)\)\s+has been detected\.""",
  ]
  DupFields = [ "file_path->malware_url" ]
}
```