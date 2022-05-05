#### Parser Content
```Java
{
Name = sigsci-web-activity
  Vendor = SIGSCI
  Product = SIGSCI
  Lms = Direct 
  DataType = "web-activity"
  TimeFormat ="yyyy-MM-dd'T'HH:ss:SSZ"
  Conditions = [ """serverHostname""", """remoteHostname""", """serverName""", """uri"""]
  Fields = [
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """"{1,20}serverHostname"{1,20}:"{1,20}({dest_host}[^"]{1,2000})""",
    """"{1,20}remoteIP"{1,20}:"{1,20}({src_ip}[^"]{1,2000})""",
    """"{1,20}remoteHostname"{1,20}:"{1,20}(|({src_host}[^"\s,]{1,2000}))"""",
    """"userAgent":"(|({user_agent}[^"]{1,2000}))"""",
    """"{1,20}timestamp"{1,20}:"{1,20}({time}[^"]{1,2000})""",
    """"{1,20}method"{1,20}:"{1,20}({method}[^"]{1,2000})""",
    """"{1,20}path"{1,20}:"{1,20}({uri_path}[^"]{1,2000})""",
    """"{1,20}responseCode"{1,20}:({result_code}\d{1,100})""",
    """"{1,20}(H|h)ost"{1,20}."{1,20}({host}[^"\]]{1,2000}?)(:\d{1,100})?"""",
    """BLOCKED"{1,20}":\s{0,100}\{"{1,20}type"{1,20}:"{1,20}({action}[^"]{1,2000})""",
    """"{1,20}protocol"{1,20}:"{1,20}({protocol}\w+\/[^"]{1,2000})""",
    """"{1,20}Content-Type"{1,20}(:|,)"{1,20}({mime}[^";]{1,2000})""",
    """"{1,20}responseSize"{1,20}:({bytes_out}\d{1,100})"""
    """"{1,20}remoteCountryCode"{1,20}:"{1,20}({src_country}[^"]{1,2000}?)",""",
    """"{1,20}tag"{1,20}:\{"{1,20}({event_code}[^"]{1,2000})"""
    ]


}
```