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
bro-activity-1 = {
  Vendor = Zeek
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """"+hostname"+:"+({host}[^"]+)"+,"+architecture""",
    """"+session_id"+:"+({session_id}[^"]+)""",
    """timestamp"+:"+({time}[^"]+)""",
    """"+user"+:"+({user}[^"]+)""",
    """"destination":\{"address"+:"+({dest_ip}[^"]+)"+,"+port"+:({dest_port}\d+)""",
    """"source":\{"address"+:"+({src_ip}[^"]+)"+,"+port"+:({src_port}\d+)""",
    """"+protocol"+:"+({protocol}[^"]+)"""
    ]

```