#### Parser Content
```Java
{
Name = cef-cloudflare-net-connection
  Vendor = Cloudflare
  Product = Cloudflare WAF
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """CEF:""", """|Skyformation|""", """requestClientApplication=""", """destinationServiceName=Cloudflare""", """dproc=Firewall""" , """cat=network-traffic"""]
  Fields = [
    """ext__occurred_at_=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    """ext_action=({activity}[^\s]+)\s""",
    """suser=({user}[^\s]+)\s""",
    """ext_ua=({user_agent}.*?)\s*\w+=""",
    """ext_country=({country_code}.*?)\s*\w+=""",
    """deviceInboundInterface=({src_interface}.*?)\s*\w+=""",
    """dhost=({dest_host}.*?)\s+\w+=""",
    """dproc=({process}.*?)\s*\w+=""",
    """ext_proto=({protocol}.*?)\s*\w+=""",
    """reason=({failure_reason}.*?)\s*\w+=""",
    """deviceDirection=({direction}.*?)\s*\w+=""",
    """dpt=({dest_port}\d+)\s""",
    """spt=({src_port}\d+)\s""",
    """src=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """dst=({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """destinationDnsDomain=({external_domain}.*?)\s*\w+=""",
    """requestClientApplication=({app}.+?)\s*\w+=""",
    """ext_source=({log_source}.+?)\s*\w+=""",
    """\sin=({bytes}.+?)\s*\w+=""",
    """ext_method=({method}[^\s]+)""",
    """cat=({category}[^\s]+)\s""",
    """cn2=({bytes}[^\s]+)\s""",
    """destinationServiceName=({dest_host}[^\s]+)\s"""
 ]
}
```