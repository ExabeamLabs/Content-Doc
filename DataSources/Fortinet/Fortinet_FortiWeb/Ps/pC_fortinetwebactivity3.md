#### Parser Content
```Java
{
Name = fortinet-web-activity-3
  Vendor = Fortinet
  Product = Fortinet FortiWeb
  Lms = Direct
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """action=""", """service=""", """app_name=""", """threat_weight=""", """main_type=""" ]
  Fields = [
    """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d+(\+|-)\d\d:\d\d)""",
    """http_host=(none|({web_domain}[^\s]{1,2000}))""",
    """src_ip=({src_ip}[a-fA-F\d\.:]{1,2000})""",
    """dst_port=({dest_port}\d{1,5})""",
    """src_port=({src_port}\d{1,5})""",
    """http_agent=(none|-|({user_agent}[^"]{1,2000}?))\s{1,100}http_refer=""",
    """http_method=(NONE|({method}[^=]{1,2000}?))\s\w+=""",
    """user_name= {1,20}(({user_email}[^\s@]{1,2000}@[^\s@]{1,2000})|({user}[^\s]{1,2000}))""",
    """http_refer=(none|({referrer}[^=]{1,2000}?))\s\w+=""",
    """http_url=(none|(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({full_url}(({protocol}[^:\\\/\s,"]{1,2000}):[\\\/]{1,2000})?({web_domain}[^\\\/\s:,"]{1,2000})?({uri_path}\/[^\s\?"]{0,2000})?({uri_query}\?[^"\s]{0,2000})?)))"""
    """app_name="({app}[^"]{1,2000})""",
    """action=({action}[^\s]{1,2000})""",
  ]


}
```