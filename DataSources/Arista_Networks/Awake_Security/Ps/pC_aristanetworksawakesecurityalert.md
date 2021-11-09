#### Parser Content
```Java
{
Name = arista-networks-awake-security-alert
  Vendor = Arista Networks
  Product = Awake Security
  Lms = Direct
  DataType = "security-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """awakesecurity""", """|Arista Networks|Awake Security|""", """DeviceUrlPath""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """deviceCustomDate1=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    """CEF:([^\|]{0,2000}\|){5}({alert_type}[^:\(]{1,2000})?\:?""",
    """CEF:([^\|]{0,2000}\|){5}[^:\(]{0,2000}[:\s]{0,100}({alert_name}[^\|]{1,2000}?)(\s\([^\)]{1,100}\))?\|""",
    """CEF:([^\|]{0,2000}\|){6}({alert_severity}\d{1,100})\|""",
    """src=({src_ip}[A-Fa-f\d:\.]{1,2000})\s{1,100}""",
    """dst=({dest_ip}[A-Fa-f\d:\.]{1,2000})\s{1,100}""",
    """shost=({src_host}[^=]{1,2000})\s{1,100}(\w{1,100}=|$)""",
    """cs3=({os}[^=]{1,2000})\s{1,100}cs3Label=""",
    """cs2=({additional_info}[^\n]{1,2000})\s{1,100}cs2Label=""",
    """CEF:([^\|]{0,2000}\|){4}({alert_id}[^\|]{1,2000})\|"""
  ]
}
}
```