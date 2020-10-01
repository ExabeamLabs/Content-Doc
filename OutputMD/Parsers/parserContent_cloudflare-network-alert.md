#### Parser Content
```Java
{
Name = cloudflare-network-alert
  Vendor = Cloudflare
  Product = Cloudflare WAF
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """CEF:""", """destinationServiceName=cloudflare""","""ext_kind=firewall"""]
  Fields = [
    """ext__occurred_at_=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    """suser=({user}.+?)\s\w+=""",
    """shost=({host}[^\s]+)""",
    """act=({alert_type}.+?)\s\w+=""",
    """cat=({alert_name}.+?)\s\w+=""",
    """\ssrc=({src_ip}[^\s]+)""",
    """dhost=({dest_host}[^\s]+)""",
    """ext__proto=({protocol}.+?)\s\w+=""",
    """spt=({src_port}[^\s]+)""",
    """dpt=({dest_port}[^\s]+)""",
  ]
}
```