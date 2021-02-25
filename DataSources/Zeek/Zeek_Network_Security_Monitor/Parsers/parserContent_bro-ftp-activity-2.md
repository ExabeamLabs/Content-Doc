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
```