#### Parser Content
```Java
{
Name = syslog-sophos-snmp-denied
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = Direct
  DataType = "file-alert"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss a"
  Conditions = [ """On-access scanner has denied access to location """, """SOPHOS:""", """SNMP Trap""", """Variable Bindings""" ]
  Fields = [
    """exabeam_host=([^=]+?@\s*)?({host}[^\s]+)""",
    """Address=({host}\S+)""",
    """({host}[\w\.-]+)\s+MSWinEventLog""",
    """\sReceived Time:({time}\d\d\d\d-\d\d-\d\d \d{1,2}:\d\d:\d\d (AM|PM|am|pm))""",
    """\sSource:({src_ip}[^\(\s]+)(\s*\(({src_host}[\w\.-]+)\))?""",
    """:=\s*On-access scanner has denied access to location "({file_path}(({file_parent}.+)[\\\/])?({file_name}.+?))"\s+(for user\s+(({domain}.+?)\\)?({user}.+?)\s+(\S+=|$))?""",
    """({accesses}access)""",
    """({alert_name}denied access)""",
  ]
  DupFields = ["alert_name->alert_type"]
}
```