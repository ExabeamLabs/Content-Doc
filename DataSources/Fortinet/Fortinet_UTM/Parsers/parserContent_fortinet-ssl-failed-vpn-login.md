#### Parser Content
```Java
{
Name = fortinet-ssl-failed-vpn-login
  DataType = "failed-vpn-login"
  TimeFormat = "yyyy-MM-dd 'time='HH:mm:ssZ"
  Conditions = [ """action="ssl-login-fail"""", """subtype="vpn"""" ]
  Fields = ${FortinetParserTemplates.fortinet-ssl-vpn.Fields} [
    """reason="({failure_reason}[^"]+)""",
  ]
}
fortinet-ssl-vpn = {
  Vendor = Fortinet
  Product = Fortinet VPN
  Lms = Splunk
  Fields = [
    """({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d),[^,]*,({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """date=({time}\d\d\d\d-\d\d-\d\d time=\d\d:\d\d:\d\d([+-]\d\d:\d\d)?)""",
    """\Wdevname="{0,20}({host}[\w\-.]+)""",
    """\Wremip=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wtunnelip=(\(null\)|({src_translated_ip}[A-Fa-f:\d.]+))""",
    """\Wuser="(.+?\\\\)?(?:N\/A|({user}[^\s@"]+))"""",
    """\Wuser="(?:N\/A|({user_email}[^\s@"]+@[^\s@"]+))"""",
    """\Wmsg="({event_code}[^"]+)""",
    """\Wsentbyte=({bytes_out}\d{1,100})""",
    """\Wrcvdbyte=({bytes_in}\d{1,100})""",
    """\Wgroup="({realm}[^"]+)""", 
  ]

```