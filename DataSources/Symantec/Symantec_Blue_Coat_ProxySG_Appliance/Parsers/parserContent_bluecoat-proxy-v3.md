#### Parser Content
```Java
{
Name = bluecoat-proxy-v3
  Vendor = Symantec
  Product = Symantec Blue Coat ProxySG Appliance
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "MM/dd/yyyy HH:mm:ss"
  Conditions = [ """action=""" , """TCP""", """cs_host""" , """cs_method=""", """src_ip"""]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}[\w.-]+)""",
    """Time="({time}\d{1,100}/\d{1,100}/\d{1,100}\s\d{1,100}:\d{1,100}:\d{1,100})""",
    """user=({user}[^\s,"]+)""",
    """action="?({action}[^"\s,]+)""",
    """src_ip="({src_ip}[^"]+)""",
    """Browser="({browser}[^"]+)""",
    """cs_host="({web_domain}([^\s]+\.)?({top_domain}[^"]+\.[^"]+)?)""""
    """cs_method="({method}[^"]+)""",
    """bytes_out=({bytes_out}\d{1,100})""",
    """bytes_in=({bytes_in}\d{1,100})""",
    """category="({category}[^"]+)""",
    """OS="({os}[^"]+)""",
    """cs_uri_query="{0,20}(|({uri_query}[^"]+))"""",
    """http_referrer="{0,20}(|({referrer}[^"]+))"""",
    """latest\(url\)="{0,20}(|({full_url}[^"]+))""""
  ]
}
```