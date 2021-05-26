#### Parser Content
```Java
{
Name = bro-remote-logon-2
  Product = Zeek Network Security Monitor
  DataType = "remote-logon"
  Conditions = [ """protocol""", """"rdp"""", """zeek""", """type""" ]
  Fields = ${BroParserTemplates.bro-activity-1.Fields}[
    """"{1,20}rdp"{1,20}.+?result"{1,20}:"{1,20}({outcome}[^"]{1,2000})""",
  ]
}
bro-activity-1 = {
  Vendor = Zeek
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """"{1,20}hostname"{1,20}:"{1,20}({host}[^"]{1,2000})"{1,20},"{1,20}architecture""",
    """"{1,20}session_id"{1,20}:"{1,20}({session_id}[^"]{1,2000})""",
    """timestamp"{1,20}:"{1,20}({time}[^"]{1,2000})""",
    """"{1,20}user"{1,20}:"{1,20}({user}[^"]{1,2000})""",
    """"destination":\{"address"{1,20}:"{1,20}({dest_ip}[^"]{1,2000})"{1,20},"{1,20}port"{1,20}:({dest_port}\d{1,100})""",
    """"source":\{"address"{1,20}:"{1,20}({src_ip}[^"]{1,2000})"{1,20},"{1,20}port"{1,20}:({src_port}\d{1,100})""",
    """"{1,20}protocol"{1,20}:"{1,20}({protocol}[^"]{1,2000})"""
    ]

```