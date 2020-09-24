#### Parser Content
```Java
{
Name = bluecoat-proxy-v3
  Vendor = Symantec
  Product = Blue Coat ProxySG Appliance
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "MM/dd/yyyy HH:mm:ss"
  Conditions = [ """action=""" , """TCP""", """cs_host""" , """cs_method=""", """src_ip"""]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[\w.-]+)""",
    """Time="({time}\d+/\d+/\d+\s\d+:\d+:\d+)""",
    """user=({user}[^\s,"]+)""",
    """action="?({action}[^"\s,]+)""",
    """src_ip="({src_ip}[^"]+)""",
    """Browser="({browser}[^"]+)""",
    """cs_host="({web_domain}([^\s]+\.)?({top_domain}[^"]+\.[^"]+)?)""""
    """cs_method="({method}[^"]+)""",
    """bytes_out=({bytes_out}\d+)""",
    """bytes_in=({bytes_in}\d+)""",
    """category="({category}[^"]+)""",
    """OS="({os}[^"]+)""",
    """cs_uri_query="*(|({uri_query}[^"]+))"""",
    """http_referrer="*(|({referrer}[^"]+))"""",
    """latest\(url\)="*(|({full_url}[^"]+))""""
  ]
}
```