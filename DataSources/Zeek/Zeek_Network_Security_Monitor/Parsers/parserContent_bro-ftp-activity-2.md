#### Parser Content
```Java
{
Name = bro-ftp-activity-2
  Product = Zeek Network Security Monitor
  DataType = "app-activity"
  Conditions = [ """type""", """protocol""", """"ftp"""", """zeek""" ]
  Fields = ${BroParserTemplates.bro-activity-1.Fields}[
    """"+msg"+:"+({additional_info}[^"]+)""",
    """"+user"+:"+({user}[^"]+)""",
    """"+command"+:"+({activity}[^"]+)"""
    """ftp"+:\{"+reply.+?code"+:({trans_id}\d+)"""
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