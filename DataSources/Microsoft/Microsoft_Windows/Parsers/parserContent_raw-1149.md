#### Parser Content
```Java
{
Name = raw-1149
    Lms = Direct
    Vendor = Microsoft
    Product = Microsoft Windows
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    DataType = "remote-logon"
    Conditions = [ """Event ID: 1149""", """Remote Desktop Services: User authentication succeeded:"""  ]
    Fields = [
      """Event ID:\s*({event_code}\d+)""",
      """ComputerName(:|=)\s*({host}[\w.-]+)"""
      """TimeStamp:\s*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """User authentication succeeded:\s*User:\s*({user}[^\s]+)\s+""",
      """Domain:\s*({domain}[^\s]+)\s+""",
      """Source Network Address:\s*({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
    ]
    DupFields = [ "host->dest_host" ]
  }
```