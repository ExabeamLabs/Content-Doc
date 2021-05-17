#### Parser Content
```Java
{
Name = bro-http-web-activity-2
  Product = Zeek Network Security Monitor
  DataType = "web-activity"
  Conditions = [ """fileset""", """"http"""", """type""", """zeek""" ]
  Fields = ${BroParserTemplates.bro-activity-1.Fields}[
    """"{1,20}http"{1,20}.+?request"{1,20}:\{"{1,20}method"{1,20}:"{1,20}({method}[^"]{1,2000})"""
    """"{1,20}response"{1,20}:\{"{1,20}status_code"{1,20}:({result_code}\d{1,100})""",
    """"{1,20}request.+?referrer"{1,20}:"{1,20}({referrer}({uri_path}[^?]{1,2000})\?({uri_query}[^"]{1,2000}))""",
    """"{1,20}domain"{1,20}:"{1,20}({web_domain}[^"]{1,2000})""",
    """"{1,20}resp_mime_types"{1,20}:\["{1,20}({mime}[^"]{1,2000})"""	
  ]
}
bro-activity-1 = {
  Vendor = Zeek
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """"{1,20}hostname"{1,20}:"{1,20}({host}[^"]{1,2000})"{1,20},"{1,20}architecture""",
    """"{1,20}session_id"{1,20}:"{1,20}({session_id}[^"]{1,2000})""",
    """timestamp"{1,20}:"{1,20}({time}[^"]{1,2000})""",
    """"{1,20}user"{1,20}:"{1,20}({user}[^"]{1,2000})""",
    """"destination":\{"address"{1,20}:"{1,20}({dest_ip}[^"]{1,2000})"{1,20},"{1,20}port"{1,20}:({dest_port}\d{1,100})""",
    """"source":\{"address"{1,20}:"{1,20}({src_ip}[^"]{1,2000})"{1,20},"{1,20}port"{1,20}:({src_port}\d{1,100})""",
    """"{1,20}protocol"{1,20}:"{1,20}({protocol}[^"]{1,2000})"""
    ]

```