#### Parser Content
```Java
{
Name = bro-http-web-activity-2
  Product = Zeek Network Security Monitor
  DataType = "web-activity"
  Conditions = [ """fileset""", """"http"""", """type""", """zeek""" ]
  Fields = ${BroParserTemplates.bro-activity-1.Fields}[
    """"+http"+.+?request"+:\{"+method"+:"+({method}[^"]+)"""
    """"+response"+:\{"+status_code"+:({result_code}\d+)""",
    """"+request.+?referrer"+:"+({referrer}({uri_path}[^?]+)\?({uri_query}[^"]+))""",
    """"+domain"+:"+({web_domain}[^"]+)""",
    """"+resp_mime_types"+:\["+({mime}[^"]+)"""	
  ]
}
```