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
      """ComputerName(:|=)\s*({host}[\w.-]+)""",
      """TimeStamp:\s*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """Event ID:\s*({event_code}\d+)""",
      """({failure_reason}The application-specific permission settings do not grant ({activity}.*) permission for the COM Server application)""",
      """CLSID\s+\{({clsid}[^\}]+)\}\s+""",
      """APPID\s+\{({appid}[^\}]+)\}\s+""",
      """user\s+({domain}[^\\]+)\\({user}[^\s]+)\s+SID\s+\(({user_sid}[^\)]+)\)\s+from address\s+({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s"""
    ]
    DupFields = ["host->dest_host"]
  }
```