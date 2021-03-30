#### Parser Content
```Java
{
Name = bro-remote-logon-2
  Product = Zeek Network Security Monitor
  DataType = "remote-logon"
  Conditions = [ """protocol""", """"rdp"""", """zeek""", """type""" ]
  Fields = ${BroParserTemplates.bro-activity-1.Fields}[
    """"+rdp"+.+?result"+:"+({outcome}[^"]+)""",
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