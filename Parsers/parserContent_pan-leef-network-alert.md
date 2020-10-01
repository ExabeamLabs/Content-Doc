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
    """LEEF:[^\|]+\|[^\|]+\|[^\|]+\|[^\|]+\|({alert_name}[^\|]+)\|""",
    """Subtype=({alert_type}[^\s\|]+)\s*\|""",
    """devTime=({time}[^\|]+)\s*\|""",
    """msg="+({additional_info}[^"]+)"""",
    """sequence=({alert_id}\d+)""",
  ]
}
```