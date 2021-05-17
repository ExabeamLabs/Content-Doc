#### Parser Content
```Java
{
Name = fortinet-dlp-alert
  Vendor = Fortinet
  Product = Fortinet UTM
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd' time='HH:mm:ss"
  Conditions = [ """subtype="dlp"""", """action=""" ]
  Fields = [ 
    """\Wdate=({time}\d\d\d\d-\d\d-\d\d time\=\d\d:\d\d:\d\d)""",
    """\Wdevname="{0,20}({host}[^\s"]{1,2000})"{0,20}(\s|")""",
    """\Wsrcip=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wdstip=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wseverity="({alert_severity}[^"]{1,2000})"""",
    """\Wsubtype="({alert_type}[^"]{1,2000})"""",
    """\Wurl="({target}[^"]{1,2000})"""",
    """\Wuser="({user}[^"]{1,2000})"""",
    """\Wfiltertype="({alert_name}[^"]{1,2000})"""",
    """\Waction="({action}[^"]{1,2000})"""",
    """\Wsrcport=({src_port}\d{1,100})""",
    """\Wdstport=({dest_port}\d{1,100})""",
    """\Wservice="({protocol}[^"]{1,2000})"""",
  ]
}
```