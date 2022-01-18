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
      """Event ID:\s{0,100}({event_code}\d{1,100})""",
      """ComputerName(:|=)\s{0,100}({host}[\w.-]{1,2000})""" 
      """TimeStamp:\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """({app}Rdp)CoreTS""",
      """({activity}Channel ({channel}[^\s]{1,2000}) has been closed between the server and the client)"""
    ]
    DupFields = [ "host->dest_host" ]
  

}
```