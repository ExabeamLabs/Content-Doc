#### Parser Content
```Java
{
Name = raw-10016
    Lms = Direct
    Vendor = Microsoft
    Product = Microsoft Windows
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    DataType = "dcom-activation-failed"
    Conditions = ["""Event ID: 10016""","""The application-specific permission settings do not grant""","""for the COM Server application"""]
    Fields = [
      """ComputerName(:|=)\s{0,100}({host}[\w.-]+)""",
      """TimeStamp:\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """Event ID:\s{0,100}({event_code}\d{1,100})""",
      """({failure_reason}The application-specific permission settings do not grant ({activity}.*) permission for the COM Server application)""",
      """CLSID\s{1,100}\{({clsid}[^\}]+)\}\s{1,100}""",
      """APPID\s{1,100}\{({appid}[^\}]+)\}\s{1,100}""",
      """user\s{1,100}({domain}[^\\]+)\\({user}[^\s]+)\s""",
      """\s{1,100}SID\s{1,100}\(({user_sid}[^\)]+)\)\s{1,100}from address\s{1,100}(({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})|({src_host}[^\s]+))\s"""
    ]
    DupFields = ["host->dest_host"]
  }
```