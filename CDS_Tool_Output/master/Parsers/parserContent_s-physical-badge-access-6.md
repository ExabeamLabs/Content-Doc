#### Parser Content
```Java
{
Name = s-physical-badge-access-6
    Vendor = Unknown
  Product = Unknown
    Lms = Splunk
    DataType = "physical-access"
    TimeFormat = "MM/dd/yyyy HH:mm:ss"
    Conditions = ["AccessDescription","PersonnelID"]
    Fields = [
      """AccessFormatedTime"+:"+({time}\d\d/\d\d/\d\d\d\d \d\d:\d\d:\d\d)""",
      """AccesshostName":"({host}[^"]+)""",
      """PersonnelID":"({user}[^"]+)""",
      """PersonName":"({user_fullname}[^"]+)""",
      """PersonID":"({employee_id}[^"]+)""",
      """AccessDescription":"({outcome}[^"]+)""",
      """ReaderName":"({location_city}\w+)""",
      """ReaderName":"({location_door}[^"]+)"""
    ]
  }
```