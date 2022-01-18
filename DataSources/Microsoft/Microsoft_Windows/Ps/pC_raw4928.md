#### Parser Content
```Java
{
Name = raw-4928
    Lms = Direct
    Vendor = Microsoft
    Product = Microsoft Windows
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    DataType = "ds-access"
    Conditions = ["""Event ID: 4928""","""An Active Directory replica source naming context was established"""]
    Fields = [
      """ComputerName(:|=)\s{0,100}({host}[\w.-]{1,2000})""",
      """TimeStamp:\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """Event ID:\s{0,100}({event_code}\d{1,100})""",
      """({activity_type}replica source naming context was established)""",
      """Destination DRA:\s{0,100}({object}CN=.*?DC=.*?)\s""",
      """Source DRA:\s{0,100}({src_object}CN=.*?DC=.*?)\s""",
      """Source Address:\s{0,100}({src_host}[^\s]{1,2000})\s""",
      """Naming Context:\s{0,100}({naming_context}[^\s]{1,2000})\s""",
      """Options:\s{0,100}({options}[^\s]{1,2000})\s""",
      """Status Code:\s{0,100}({status_code}\d{1,100})"""
    ]
    DupFields = ["host->dest_host"]
  

}
```