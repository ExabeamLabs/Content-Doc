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
      """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """\d\d:\d\d:\d\d\s{1,100}(?:-|\d{1,100}\s{1,100}){4}(?:-|({dest_ip}[^\s]+))\s{1,100}(?:-|({src_ip}[^\s]+))\s{1,100}(?:-|"{0,20}({user_email}[^"]+)"{0,20})\s{1,100}(?:-|({method}[^\s]+))\s{1,100}(?:-|({protocol}[^\s]+))\s{1,100}(?:-|({uri_query}[^\s]+))\s{1,100}(?:-|"{0,20}({user_agent}[^"]+)"{0,20})\s{1,100}(?:-|"{0,20}({category}[^"]+)"{0,20})\s{1,100}(?:-|({result_code}\d{1,100}))\s{1,100}(?:-|"{0,20}({mime}[^"]+)"{0,20})\s{1,100}(?:-|({web_domain}[^\s]+))\s{1,100}(?:-|({top_domain}[^\s]+))\s{1,100}(?:-|({uri_path}[^\s]+))\s{1,100}(?:-|\d{1,100})\s{1,100}(?:-|({full_url}[^\s]+))\s{1,100}(?:-|\d{1,100})\s{1,100}(?:-|"{0,20}([^"]+)"{0,20})\s{1,100}(?:-|"{0,20}({app}[^"]+)"{0,20})\s{1,100}(?:-|"{0,20}({country_code}[^"]+)"{0,20})\s{1,100}(?:-|({latitude}[^\s]+))\s{1,100}(?:-|({longitude}[^\s]+))\s{1,100}(?:-|"{0,20}({location_city}[^"]+)"{0,20})\s{1,100}(?:-|"{0,20}({location_state}[^"]+)"{0,20})\s{1,100}(?:N\/A|-|\d{1,100})\s{1,100}(?:-|"{0,20}({country}[^"]+)"{0,20})""",
      """(?:-|"({additional_info}[^"]+)")\s{1,100}http_transaction"""
    ]
  }
```