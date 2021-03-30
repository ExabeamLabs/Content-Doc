#### Parser Content
```Java
{
Name = cef-fortinet-auth-successful
  Vendor = Fortinet
  Product = Fortinet UTM
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd 'time\\='HH:mm:ss"
  Conditions = [ """CEF:0|Fortinet|Fortigate""", """status\="success"""", """action\="NTLM-auth"""", """ logdesc\=""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """date\\=({time}\d\d\d\d-\d\d-\d\d time\\=\d\d:\d\d:\d\d)""",
    """devname\\="*({host}[^"]+?)"*(\s+\w+\\=|\s*$)""",
    """\ssrcip\\="?({src_ip}[a-fA-F\d.:]+)""",
    """\sdstip\\="?({dest_ip}[a-fA-F\d.:]+)""",
    """\suser\\="*(N\/A|({user}[^"]+?))"*(\s+\w+\\=|\s*$)""",
    """\slogdesc\\="({event_name}[^"]+)""",
    """\sdevid\\="({dest_host}[^"]+)""",
  ]
}
```