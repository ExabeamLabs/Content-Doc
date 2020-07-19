#### Parser Content
```Java
{
Name = pan-leef-network-alert
  Vendor = Palo Alto Networks
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
		
{
  Name = pan-auth-successful-2
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """panorama-auth-success""", """,SYSTEM,tls,""" ]
  Fields = [
    """\w+\s+\d+\s+\d+:\d+:\d+\s+({host}[\w\-.]+)\s+\d+,({time}\d+\/\d+\/\d+\s+\d+:\d+:\d+),""",
    """Client IP:\s*({src_ip}[A-Fa-f:\d.]+)""",
    """Server IP:\s*({dest_ip}[A-Fa-f:\d.]+)""",
    ]
}
```