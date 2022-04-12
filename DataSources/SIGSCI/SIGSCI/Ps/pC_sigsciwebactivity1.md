#### Parser Content
```Java
{
Name = sigsci-web-activity-1
  Vendor = SIGSCI
  Product = SIGSCI
  Lms = Direct
  DataType = "web-activity"
  TimeFormat ="yyyy-MM-dd'T'HH:ss:SSZ"
  Conditions = [ """"serverHostName"="""", """"remoteHostname"="""", """"serverName"="""", """"uri"=""""]
  Fields = [
    """"{1,20}serverName"{1,20}="{1,20}({host}[\w\.-]{1,2000})"""
    """"{1,20}serverHostName"{1,20}="{1,20}({dest_host}[^"]{1,2000})""",
    """"{1,20}remoteIP"{1,20}="{1,20}({src_ip}[^"]{1,2000})""",
    """"{1,20}remoteHostname"{1,20}="{1,20}(,|({src_host}[^"]{1,2000}))""",
    """"{1,20}userAgent"{1,20}="{1,20}(,|({user_agent}[^"]{1,2000}))""",
    """"{1,20}timestamp"{1,20}="{1,20}({time}[^"]{1,2000})""",
    """"{1,20}method"{1,20}="{1,20}(,|({method}[^"]{1,2000}))""",
    """"{1,20}path"{1,20}="{1,20}({uri_path}[^"]{1,2000})""",
    """"{1,20}responseCode"{1,20}="{1,20}({result_code}\d{1,100})""",   
    """"{1,20}protocol"{1,20}="{1,20}(,|({protocol}[^"]{1,2000}))""", 
    """"{1,20}responseSize"{1,20}="{1,20}({bytes_out}\d{1,100})"""
    """"{1,20}remoteCountryCode"{1,20}="{1,20}({src_country}[^"]{1,2000}?)",""",
    """"{1,20}tag"{1,20}="{1,20}({event_code}[^"]{1,2000})"""
    ]


}
```