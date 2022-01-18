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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w.-]{1,2000})""",
    """Time="({time}\d{1,100}/\d{1,100}/\d{1,100}\s\d{1,100}:\d{1,100}:\d{1,100})""",
    """user=({user}[^\s,"]{1,2000})""",
    """action="?({action}[^"\s,]{1,2000})""",
    """src_ip="({src_ip}[^"]{1,2000})""",
    """Browser="({browser}[^"]{1,2000})""",
    """cs_host="({web_domain}([^\s]{1,2000}\.)?({top_domain}[^"]{1,2000}\.[^"]{1,2000})?)""""
    """cs_method="({method}[^"]{1,2000})""",
    """bytes_out=({bytes_out}\d{1,100})""",
    """bytes_in=({bytes_in}\d{1,100})""",
    """category="({category}[^"]{1,2000})""",
    """OS="({os}[^"]{1,2000})""",
    """cs_uri_query="{0,20}(|({uri_query}[^"]{1,2000}))"""",
    """http_referrer="{0,20}(|({referrer}[^"]{1,2000}))"""",
    """latest\(url\)="{0,20}(|({full_url}[^"]{1,2000}))""""
  ]


}
```