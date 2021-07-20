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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """devTime=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """LEEF:([^\|]{0,2000}\|){4}({alert_name}[^\|]{1,2000})""",
    """cat=({alert_type}[^=\|\#]{1,2000})""",
    """proto=({protocol}[^\=\|\#]{1,2000})""",
    """sev=({alert_severity}[^\=\|\#]{1,2000})""",
    """src=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """dst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """srcPort=({src_port}\d{1,100})""",
    """dstPort=({dest_port}\d{1,100})""",
    """status=({action}[^\=\|\#]{1,2000})""",
  ]
}
```