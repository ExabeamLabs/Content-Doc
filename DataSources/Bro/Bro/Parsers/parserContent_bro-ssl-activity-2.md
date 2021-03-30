#### Parser Content
```Java
{
Name = bro-ssl-activity-2
  Product = Bro
  DataType = "authentication-successful"
  Conditions = [ """dataset""", """"ssl"""", """zeek""", """type""", """established""" ]
  Fields = ${BroParserTemplates.bro-activity-1.Fields}[
    """"+server"+.+?name"+:"+({server}[^"]+)""",
    """zeek"+.+?established"+:({outcome}[^,]+)""",
    """zeek"+.+?version"+:"+({version}[^"]+)"+,"+cipher"+:"+({auth_method}[^"]+)"""
    ]
}
bro-activity-1 = {
  Vendor = Bro
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