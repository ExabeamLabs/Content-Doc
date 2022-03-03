#### Parser Content
```Java
{
Name = apache-web-activity-1
  Vendor = Apache
  Product = Apache
  Lms = Splunk
  DataType = "web-activity"
  TimeFormat = epoch
  Conditions = [ """ user="""", """ http_content_type="""", """ client=""", """ http_method="""", """ uri_path="""" ] 
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """time=({time}\d{10}\.\d{1,6}),""", 
    """user="{1,20}(-|({user}[^"]{1,2000}))"""",
    """http_method="{1,20}({method}[^"]{1,2000})"""",
    """server=({web_domain}[\w._-]{1,2000}),""",
    """client=({src_ip}[A-Za-z0-9\.:]{1,2000})""",
    """uri_path="{1,20}({uri_path}[^"]{1,2000})"""",
    """dest_port=({dest_port}\d{1,2000})""",
    """bytes_in=({bytes_in}\d{1,2000})""",
    """bytes_out=({bytes_out}\d{1,2000})""",
    """http_user_agent="{1,20}({user_agent}[^"]{1,2000})"""",
    """status=({result_code}\d{1,2000})""",
    """http_content_type="{1,20}(-|({mime}[^"]{1,2000}))"""",
    """http_referrer="{1,20}(-|({referrer}[^"]{1,2000}))"""",
    """uri_query="{1,20}\?({uri_query}[^"]{1,2000})""""
  ]


}
```