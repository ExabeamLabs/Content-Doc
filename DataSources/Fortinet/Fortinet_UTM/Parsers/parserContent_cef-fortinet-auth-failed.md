#### Parser Content
```Java
{
Name = cef-fortinet-auth-failed
  Vendor = Fortinet
  Product = Fortinet UTM
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd 'time\\='HH:mm:ss"
  Conditions = [ """CEF:0|Fortinet|Fortigate""", """status\="failure"""", """action\="NTLM-auth"""", """ logdesc\=""" ]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """date\\=({time}\d\d\d\d-\d\d-\d\d time\\=\d\d:\d\d:\d\d)""",
    """devname\\="{0,20}({host}[^"]{1,2000}?)"{0,20}(\s{1,100}\w+\\=|\s{0,100}$)""",
    """\ssrcip\\="?({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\sdstip\\="?({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\suser\\="{0,20}(N\/A|({user}[^"]{1,2000}?))"{0,20}(\s{1,100}\w+\\=|\s{0,100}$)""",
    """\slogdesc\\="({event_name}[^"]{1,2000})""",
    """\sdevid\\="({dest_host}[^"]{1,2000})""",
  ]
}
```