#### Parser Content
```Java
{
Name = raw-148
    Lms = Direct
    Vendor = Microsoft
    Product = Microsoft Windows
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    DataType = "logout-remote"
    Conditions = [ """Event ID: 148""", """has been closed between the server"""  ]
    Fields = [ 
      """Event ID:\s*({event_code}\d+)""",
      """ComputerName(:|=)\s*({host}[\w.-]+)""" 
      """TimeStamp:\s*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """({app}Rdp)CoreTS""",
      """({activity}Channel ({channel}[^\s]+) has been closed between the server and the client)"""
    ]
    DupFields = [ "host->dest_host" ]
  }
```