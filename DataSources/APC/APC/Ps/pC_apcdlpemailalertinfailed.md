#### Parser Content
```Java
{
Name = apc-dlp-email-alert-in-failed
  Vendor = APC
  Product = APC
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd 'time='HH:mm:ss.SSS"
  Conditions = [ """type=statistics """, """classifier="Access Control-Reject"""", """disposition="Reject"""", """direction="in"""" ]
  Fields = [
    """date=({time}\d\d\d\d-\d\d-\d\d\stime=\d\d:\d\d:\d\d\.\d{1,3})""",
    """pri=({alert_severity}[^\s]{1,2000})""",
    """client_name="({src_host}[^"]{1,2000})"""",
    """client_ip="({src_ip}[a-fA-F\d:\.]{1,2000})"""",
    """dst_ip="({dest_ip}[a-fA-F\d:\.]{1,2000})"""",
    """from="({sender}[^"]{1,2000})"""",
    """to="({recipient}[^"]{1,2000})"""",
    """domain="({domain}[^"]{1,2000})"""",
    """direction="({direction}[^"]{1,2000})"""",
    """classifier="({alert_name}[^"]{1,2000})"""",
    """disposition="({action}[^"]{1,2000})"""",
    """subject="({subject}[^"]{1,2000})""""
  ]


}
```