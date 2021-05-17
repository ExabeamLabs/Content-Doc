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
    """ext_EdgeStartTimestamp=({time}[^\s]{1,2000})""",
    """suser=({user}.+?)\s\w+=""",
    """shost=({host}[^\s]{1,2000})""",
    """act=({alert_type}.+?)\s\w+=""",
    """cat=({alert_name}.+?)\s\w+=""", 
    """\ssrc=({src_ip}[^\s]{1,2000})""",
    """dst=({dest_ip}[^\s]{1,2000})""",
    """dhost=({dest_host}[^\s]{1,2000})""",
    """proto=({protocol}.+?)\s\w+=""",
    """spt=({src_port}[^\s]{1,2000})""",
    """dpt=({dest_port}[^\s]{1,2000})""",
  ]
}
```