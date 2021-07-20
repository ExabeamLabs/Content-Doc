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
    """"{1,20}serverHostname"{1,20}:"{1,20}({src_host}[^"]{1,2000})""",
    """"{1,20}remoteIP"{1,20}:"{1,20}({dest_ip}[^"]{1,2000})""",
    """"{1,20}remoteHostname"{1,20}:"{1,20}({dest_host}[^"]{1,2000}),""",
    """"{1,20}userAgent"{1,20}:"{1,20}({user_agent}[^"]{1,2000})""",
    """"{1,20}timestamp"{1,20}:"{1,20}({time}[^"]{1,2000})""",
    """"{1,20}method"{1,20}:"{1,20}({method}[^"]{1,2000})""",
    """"{1,20}path"{1,20}:"{1,20}({uri_path}[^"]{1,2000})""",
    """"{1,20}responseCode"{1,20}:({result_code}\d{1,100})""",
    """"{1,20}Host"{1,20}."{1,20}({host}[^"]{1,2000})""",
    """BLOCKED"{1,20}":\s{0,100}\{"{1,20}type"{1,20}:"{1,20}({action}[^"]{1,2000})""",
    """"{1,20}protocol"{1,20}:"{1,20}({protocol}[^"]{1,2000})""",
    """"{1,20}Content-Type"{1,20}:"{1,20}({mime}[^";]{1,2000})""",
    """"{1,20}responseSize"{1,20}:({bytes_out}\d{1,100})"""
    ]
}
```