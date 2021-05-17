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
    """\Wdevname="{0,20}({host}[^\s"]{1,2000})"{0,20}(\s|")""",
    """\Wsrcip=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wdstip=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wattack="({alert_name}[^"]{1,2000})"""",
    """\Wsubtype="({alert_type}[^"]{1,2000})"""",
    """\Wattackid=({alert_id}\d{1,100})(\s|")""",
    """\Wref="({malware_url}[^"]{1,2000})"""",
    """\Wmsg="({additional_info}[^"]{1,2000})"""",
    """\Wuser="({user}[^"]{1,2000})"""",
    """\Wcrlevel="{0,20}({alert_severity}[^"\s]{1,2000})(\s|")""",
    """\Wsrcport=({src_port}\d{1,100})""",
    """\Wdstport=({dest_port}\d{1,100})""",
    """\Wservice="({protocol}[^"]{1,2000})"""",
    """\Waction="({action}[^"]{1,2000})"""",
  ]
  DupFields = ["malware_url->process_name"]
}
```