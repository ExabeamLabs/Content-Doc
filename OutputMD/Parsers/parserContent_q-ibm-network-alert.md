#### Parser Content
```Java
{
Name = q-ibm-network-alert
  Vendor = IBM
  Product = Proventia Network IPS
  Lms = QRadar
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """LEEF:""", """|IBM|NIPS|""", """cat=Attack""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """devTime=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """LEEF:([^\|]*\|){4}({alert_name}[^\|]+)""",
    """cat=({alert_type}[^=\|\#]+)""",
    """proto=({protocol}[^\=\|\#]+)""",
    """sev=({alert_severity}[^\=\|\#]+)""",
    """src=({src_ip}[A-Fa-f:\d.]+)""",
    """dst=({dest_ip}[A-Fa-f:\d.]+)""",
    """srcPort=({src_port}\d+)""",
    """dstPort=({dest_port}\d+)""",
    """status=({action}[^\=\|\#]+)""",
  ]
}
```