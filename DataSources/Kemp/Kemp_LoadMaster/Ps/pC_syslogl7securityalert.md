#### Parser Content
```Java
{
Name = syslog-l7-security-alert
  Vendor = Kemp
  Product = Kemp LoadMaster
  Lms = Direct
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """ l7log:""", """ Attempted """, """ attack on """ ]
  Fields = [
    """exabeam_host=({host}[\w\.\-]{1,2000})""",
    """\s({host}[\w\.\-]{1,2000})\s{1,100}\S+\s{1,100}\S+\s{1,100}l7log:""",
    """attack on\s{1,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\s{1,100}from\s{1,100}({malware_url}[^\(\s]{1,2000})\s{1,100}\(({additional_info}.+?)\)""",
    """\sAttempted\s{1,100}({alert_name}.+?)\s{1,100}on""",
  ]
  DupFields = [ alert_name->alert_type ]
}
```