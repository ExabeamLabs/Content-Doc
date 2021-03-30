#### Parser Content
```Java
{
Name = q-aruba-failed-nac-logon-1
  DataType = "nac-failed-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss-SS"
  Conditions = [ """ Failed Auth """, """Common.NAS-IP-Address=""" ]
  Fields = ${HPEParserTemplates.q-aruba-nac-logon.Fields} [
    """Common\.Request-Timestamp=({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d-\d+)"""
]
}
q-aruba-nac-logon = {
  Vendor = HPE
  Product = Aruba ClearPass Access Control and Policy Management
  Lms = QRadar
  TimeFormat = "yyyy-MM-dd HH:mm:ssZ"
  Fields = [
    """Common\.Request-Timestamp=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d(\.\d+)?[\+\-]\d+)""",
    """\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d,\d+ ({host}[\w\-.]+)""",
    """Common\.Username=(?:({user_type}host)/)?(({domain}[^\\\s,]+)\\+)?(anonymous|({user}[^\\\s,@]+))""",
    """Common\.Username=({user_email}[^\\\s,@]+@[^\\\s,@]+)""",
    """Common\.Service=({network}[^,]+)""",
    """Common\.Host-MAC-Address=({src_mac}\w+)""",
    """Common\.NAS-IP-Address=({dest_ip}[A-Fa-f:\d.]+)"""
  ]

```