#### Parser Content
```Java
{
Name = cloudflare-network-alert-2
  Vendor = Cloudflare
  Product = Cloudflare CDN
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """destinationServiceName=cloudflare""", """ext_EdgeStartTimestamp=""" ]
  Fields = [
    """ext_EdgeStartTimestamp=({time}[^\s]+)""",
    """suser=({user}.+?)\s\w+=""",
    """shost=({host}[^\s]+)""",
    """act=({alert_type}.+?)\s\w+=""",
    """cat=({alert_name}.+?)\s\w+=""", 
    """\ssrc=({src_ip}[^\s]+)""",
    """dst=({dest_ip}[^\s]+)""",
    """dhost=({dest_host}[^\s]+)""",
    """proto=({protocol}.+?)\s\w+=""",
    """spt=({src_port}[^\s]+)""",
    """dpt=({dest_port}[^\s]+)""",
  ]
}
```