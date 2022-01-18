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
      """Event ID:\s{0,100}({event_code}\d{1,100})""",
      """ComputerName(:|=)\s{0,100}({host}[\w.-]{1,2000})"""
      """TimeStamp:\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """User authentication succeeded:\s{0,100}User:\s{0,100}({user}[^\s]{1,2000})\s{1,100}""",
      """Domain:\s{0,100}({domain}[^\s]{1,2000})\s{1,100}""",
      """Source Network Address:\s{0,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
    ]
    DupFields = [ "host->dest_host" ]
  

}
```