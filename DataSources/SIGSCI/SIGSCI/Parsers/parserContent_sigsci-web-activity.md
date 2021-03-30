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
    """"+serverHostname"+:"+({src_host}[^"]+)""",
    """"+remoteIP"+:"+({dest_ip}[^"]+)""",
    """"+remoteHostname"+:"+({dest_host}[^"]+),""",
    """"+userAgent"+:"+({user_agent}[^"]+)""",
    """"+timestamp"+:"+({time}[^"]+)""",
    """"+method"+:"+({method}[^"]+)""",
    """"+path"+:"+({uri_path}[^"]+)""",
    """"+responseCode"+:({result_code}\d+)""",
    """"+Host"+."+({host}[^"]+)""",
    """BLOCKED"+":\s*\{"+type"+:"+({action}[^"]+)""",
    """"+protocol"+:"+({protocol}[^"]+)""",
    """"+Content-Type"+:"+({mime}[^";]+)""",
    """"+responseSize"+:({bytes_out}\d+)"""
    ]
}
```