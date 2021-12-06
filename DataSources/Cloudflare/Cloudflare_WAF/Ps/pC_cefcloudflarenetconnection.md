#### Parser Content
```Java
{
Name = cef-cloudflare-net-connection
  Vendor = Cloudflare
  Product = Cloudflare WAF
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """requestClientApplication=""", """destinationServiceName =Cloudflare""", """dproc=Firewall""" , """cat=network-traffic"""]
  Fields = [
    """ext__occurred_at_=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    """"action":"({activity}[^"]{1,2000})"""",
    """suser=({user}[^\s]{1,2000})\s""",
    """"ua":"({user_agent}[^"]*?)"""",
    """"country":"({country_code}[^"]*?)"""",
    """deviceInboundInterface=({src_interface}.*?)\s{0,100}\w+=""",
    """dhost=({dest_host}.*?)\s{1,100}\w+=""",
    """dproc=({process}.*?)\s{0,100}\w+=""",
    """ext_proto=({protocol}.*?)\s{0,100}\w+=""",
    """reason=({failure_reason}.*?)\s{0,100}\w+=""",
    """deviceDirection=({direction}.*?)\s{0,100}\w+=""",
    """dpt=({dest_port}\d{1,100})\s""",
    """spt=({src_port}\d{1,100})\s""",
    """src=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """dst=({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """requestClientApplication=({app}.+?)\s{0,100}\w+=""",
    """"source":"({log_source}[^"]+?)"""",
    """\sin=({bytes}.+?)\s{0,100}\w+=""",
    """ext_method=({method}[^\s]{1,2000})""",
    """cat=({category}[^\s]{1,2000})\s""",
    """cn2=({bytes}[^\s]{1,2000})\s""",
    """destinationServiceName =({dest_host}[^\s]{1,2000})\s"""
 ]


}
```