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
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[^\s]{1,2000})""",
    """Address=({host}\S+)""",
    """({host}[\w\.-]{1,2000})\s{1,100}MSWinEventLog""",
    """\sReceived Time:({time}\d\d\d\d-\d\d-\d\d \d{1,2}:\d\d:\d\d (AM|PM|am|pm))""",
    """\sSource:({src_ip}[^\(\s]{1,2000})(\s{0,100}\(({src_host}[\w\.-]{1,2000})\))?""",
    """:=\s{0,100}On-access scanner has denied access to location "({file_path}(({file_parent}.+)[\\\/])?({file_name}.+?))"\s{1,100}(for user\s{1,100}(({domain}.+?)\\)?({user}.+?)\s{1,100}(\S+=|$))?""",
    """({accesses}access)""",
    """({alert_name}denied access)""",
  ]
  DupFields = ["alert_name->alert_type"]
}
```