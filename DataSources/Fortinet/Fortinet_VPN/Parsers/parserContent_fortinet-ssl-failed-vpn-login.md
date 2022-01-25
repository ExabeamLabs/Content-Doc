#### Parser Content
```Java
{
Name = fortinet-ssl-failed-vpn-login
  DataType = "failed-vpn-login"
  TimeFormat = "yyyy-MM-dd 'time='HH:mm:ssZ"
  Conditions = [ """action="ssl-login-fail"""", """subtype="vpn"""" ]
  Fields = ${FortinetParserTemplates.fortinet-ssl-vpn.Fields} [
    """reason="({failure_reason}[^"]{1,2000})""",
  ]
}
fortinet-ssl-vpn = {
  Vendor = Fortinet
  Product = Fortinet VPN
  Lms = Splunk
  Fields = [
    """({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d),[^,]{0,2000},({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """date=({time}\d\d\d\d-\d\d-\d\d time=\d\d:\d\d:\d\d([+-]\d\d:\d\d)?)""",
    """\Wdevname="{0,20}({host}[\w\-.]{1,2000})""",
    """\Wremip=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wtunnelip=(\(null\)|({src_translated_ip}[A-Fa-f:\d.]{1,2000}))""",
    """\Wuser="(.+?\\\\)?(?:N\/A|({user}[^\s@"]{1,2000}))"""",
    """\Wuser="(?:N\/A|({user_email}[^\s@"]{1,2000}@[^\s@"]{1,2000}))"""",
    """\Wmsg="({event_code}[^"]{1,2000})""",
    """\Wsentbyte=({bytes_out}\d{1,100})""",
    """\Wrcvdbyte=({bytes_in}\d{1,100})""",
    """\Wgroup="({realm}[^"]{1,2000})""", 
  ]

```