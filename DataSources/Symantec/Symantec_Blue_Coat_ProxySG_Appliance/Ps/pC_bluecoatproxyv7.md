#### Parser Content
```Java
{
Name = bluecoat-proxy-v7
  Conditions = [ """method="GET"""", """OBSERVED""", """event_type="web-activity-allowed"""", """http""" ]

bluecoat-proxy-1 = {
  Vendor = Symantec
  Product = Symantec Blue Coat ProxySG Appliance
  Lms = Syslog
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """timestamp="({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)"""",
    """user="({user}[^"]{1,2000})"""",
    """src_host="({src_host}[^"]{1,2000})"""",
    """src_ip="({src_ip}[a-fA-F\d:.]{1,2000})"""",
    """method="({method}[^"]{1,2000})"""",
    """bytes_in="({bytes_in}\d{1,100})"""",
    """bytes_out="({bytes_out}\d{1,100})"""",
    """browser="({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident|Mozilla)"""",
    """os="({os}[^"]{1,2000})"""",
    """full_url="({full_url}(({protocol}[^:]{1,2000}):\/+)?[^"]{1,2000})"""",
    """web_domain="({web_domain}[^"]{1,2000})"""",
    """proxy_action="({proxy_action}[^"]{1,2000})"""",
    """category="({category}[^"]{1,2000})"""",
    """\saction="({action}[^"]{1,2000})"""",
    """rule_name="({rule}[^"]{1,2000})"""",
    """uri_path="({uri_path}[^"]{1,2000})"""",
    """uri_query="({uri_query}[^"]{1,2000})"""",
    """referrer="({referrer}[^"]{1,2000})""""
  
}
```