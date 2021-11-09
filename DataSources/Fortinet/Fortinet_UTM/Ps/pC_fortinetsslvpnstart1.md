#### Parser Content
```Java
{
Name = fortinet-ssl-vpn-start-1
  DataType = "vpn-start"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """action="tunnel-up"""", """subtype="vpn"""" ]
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
  DupFields = ["host->dest_host", "user->account"]}
```