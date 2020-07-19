#### Parser Content
```Java
{
Name = bro-dhcp-activity-2
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
```