#### Parser Content
```Java
{
Name = barracuda-remote-logon
  DataType = "remote-logon"
  Conditions = [ """ LOGIN ATTEMPT: """, """ Info """, """ : Allowed""", """box_Auth_access:""", """: Login """ ]
}
barracuda-logon-activity = {
  Vendor = Barracuda
  Product = Barracuda Firewall
  Lms = Direct
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d\s({host}\S+)""",
    """Login (|({user}[^\s]{1,2000})\s)from ({src_ip}[a-fA-F\d:.]{1,2000})\s{0,100}:\s{0,100}({action}[^:.]{1,2000})(:|\.)""",
    """({event_name}LOGIN ATTEMPT)"""
  ]}
```