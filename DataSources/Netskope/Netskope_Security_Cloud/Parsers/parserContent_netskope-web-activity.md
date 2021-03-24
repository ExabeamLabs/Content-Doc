#### Parser Content
```Java
{
Name = netskope-web-activity
    Vendor = Netskope
    Product = Netskope Security Cloud
    Lms = Direct
    DataType = "web-activity"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """ http_transaction """ ]
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}\S+)""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """\d\d:\d\d:\d\d\s+(?:-|\d+\s+){4}(?:-|({dest_ip}[^\s]+))\s+(?:-|({src_ip}[^\s]+))\s+(?:-|"*({user_email}[^"]+)"*)\s+(?:-|({method}[^\s]+))\s+(?:-|({protocol}[^\s]+))\s+(?:-|({uri_query}[^\s]+))\s+(?:-|"*({user_agent}[^"]+)"*)\s+(?:-|"*({category}[^"]+)"*)\s+(?:-|({result_code}\d+))\s+(?:-|"*({mime}[^"]+)"*)\s+(?:-|({web_domain}[^\s]+))\s+(?:-|({top_domain}[^\s]+))\s+(?:-|({uri_path}[^\s]+))\s+(?:-|\d+)\s+(?:-|({full_url}[^\s]+))\s+(?:-|\d+)\s+(?:-|"*([^"]+)"*)\s+(?:-|"*({app}[^"]+)"*)\s+(?:-|"*({country_code}[^"]+)"*)\s+(?:-|({latitude}[^\s]+))\s+(?:-|({longitude}[^\s]+))\s+(?:-|"*({location_city}[^"]+)"*)\s+(?:-|"*({location_state}[^"]+)"*)\s+(?:N\/A|-|\d+)\s+(?:-|"*({country}[^"]+)"*)""",
      """(?:-|"({additional_info}[^"]+)")\s+http_transaction"""
    ]
  }
```