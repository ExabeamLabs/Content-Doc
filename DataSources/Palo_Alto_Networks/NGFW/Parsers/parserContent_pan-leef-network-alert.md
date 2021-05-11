#### Parser Content
```Java
{
Name = pan-leef-network-alert
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss z"
  Conditions = [ """LEEF:""", """|Palo Alto Networks|PAN-OS Syslog Integration|""" ,"""|Severity="""]
  Fields = [
    """Severity=({alert_severity}[^\s|]+)""",
    """DeviceName=({host}[\w\-.]+)""",
    """LEEF:([^|]*\|){4}({alert_name}[^\|]+)""",
    """Subtype=({alert_type}[^\s\|]+)\s{0,100}\|""",
    """devTime=({time}[^\|]+)\s{0,100}\|""",
    """msg="({additional_info}[^"]+)"""",
    """sequence=({alert_id}\d{1,100})""",
    """msg="(C|c)lient\s'({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'""",
  ]
}
```