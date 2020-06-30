#### Parser Content
```Java
{
Name = fortinet-security-alert-2
  Vendor = Fortinet
  Product = Fortinet UTM
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd' time='HH:mm:ss"
  Conditions = [ """subtype="anomaly"""", """action=""" ]
  Fields = [ 
    """\Wdate=({time}\d\d\d\d-\d\d-\d\d time\=\d\d:\d\d:\d\d)""",
    """\Wdevname="*({host}[^\s"]+)"*(\s|")""",
    """\Wsrcip=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wdstip=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wattack="({alert_name}[^"]+)"""",
    """\Wsubtype="({alert_type}[^"]+)"""",
    """\Wattackid=({alert_id}\d+)(\s|")""",
    """\Wref="({malware_url}[^"]+)"""",
    """\Wmsg="({additional_info}[^"]+)"""",
    """\Wuser="({user}[^"]+)"""",
    """\Wcrlevel="*({alert_severity}[^"\s]+)(\s|")"""
  ]
}
```