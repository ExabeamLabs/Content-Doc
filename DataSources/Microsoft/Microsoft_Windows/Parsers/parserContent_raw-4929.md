#### Parser Content
```Java
{
Name = raw-4929
    Lms = Direct
    Vendor = Microsoft
    Product = Microsoft Windows
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    DataType = "ds-access"
    Conditions = ["""Event ID: 4929""","""An Active Directory replica source naming context was removed"""]
    Fields = [
      """ComputerName(:|=)\s*({host}[\w.-]+)""",
      """TimeStamp:\s*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """Event ID:\s*({event_code}\d+)""",
      """({activity_type}replica source naming context was removed)""",
      """Destination DRA:\s*({object}CN=.*?DC=.*?)\s""",
      """Source DRA:\s*({src_object}CN=.*?DC=.*?)\s""",
      """Source Address:\s*({src_host}[^\s]+)\s""",
      """Naming Context:\s*({naming_context}[^\s]+)\s""",
      """Options:\s*({options}[^\s]+)\s""",
      """Status Code:\s*({status_code}\d+)"""
    ]
    DupFields = ["host->dest_host"]
  }
```