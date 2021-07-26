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
    """Severity=({alert_severity}[^\s|]{1,2000})""",
    """DeviceName=({host}[\w\-.]{1,2000})""",
    """LEEF:[^\|]{1,2000}\|[^\|]{1,2000}\|[^\|]{1,2000}\|[^\|]{1,2000}\|({alert_name}[^\|]{1,2000})\|""",
    """Subtype=({alert_type}[^\s\|]{1,2000})\s{0,100}\|""",
    """devTime=({time}[^\|]{1,2000})\s{0,100}\|""",
    """msg="{1,20}({additional_info}[^"]{1,2000})"""",
    """sequence=({alert_id}\d{1,100})""",
  ]
}
```