#### Parser Content
```Java
{
Name = bro-dhcp-activity-2
  Product = Bro
  DataType = "dhcp"
  Conditions = [ """protocol""", """"dhcp"""", """type""", """zeek""" ]
  Fields = ${BroParserTemplates.bro-activity-1.Fields}[
    """address"+:\{"+assigned"+:"+({assigned_ip}[^"]+)""",
    """"+lease_time"+:({lease_time}\d+)""",
    """dhcp"+:\{.*?hostname":"({host}[^"]+)""",
    """domain"+:"+({domain}[^"]+)""",
    """duration"+:({duration}[^,]+)""",
    """dhcp":\{"+msg.+?types"+:\[({dhcp_type}[^\]]+)"""
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