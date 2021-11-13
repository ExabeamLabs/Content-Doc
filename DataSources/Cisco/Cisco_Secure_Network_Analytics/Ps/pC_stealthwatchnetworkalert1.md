#### Parser Content
```Java
{
Name = stealthwatch-network-alert-1
    Vendor = Cisco
  Product = Cisco Secure Network Analytics
    Lms = Direct
    DataType = "network-alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """|dest_host""", """|additional_info""", """|dest_ip""" ]
    Fields = [
      """time=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\w)""",
      """\|dest_host=(|({dest_host}.+?))\|""",
      """\|additional_info=({additional_info}[^\.\|]{1,2000})""",
      """\|dest_port=(|({dest_port}.+?))\|""",
      """\|dest_ip=({dest_ip}[a-fA-F\d.:]{1,2000})""",
      """\|dest_mac=(|({dest_mac}[^\|]{1,2000}))\|""",
      """\|alert_name=(|({alert_name}[^\|]{1,2000}))\|""",
      """\|alert_type=(|({alert_type}[^\|]{1,2000}))\|""",
      """\|src_host=(|({src_host}[^\|]{1,2000}))\|""",
      """\|alert_severity=({alert_severity}\d{1,100})\|""",
      """\|src_ip=({src_ip}[a-fA-F\d.:]{1,2000})""",
      """\|src_mac=({src_mac}[a-fA-F\d.:]{1,2000})""",
      """\|user=(|({user}[^\|]{1,2000}))\|""",
      """\|host_ip=({host_ip}[a-fA-F\d.:]{1,2000})""",
      """\|host=({host}[^\|]{1,2000})""",
      """\|protocol=(|({protocol}[^\|]{1,2000}))\|""",
      """\|alert_id=({alert_id}[^\|]{1,2000}?)(\||\s{0,100}$)""",
    ]
  

}
```