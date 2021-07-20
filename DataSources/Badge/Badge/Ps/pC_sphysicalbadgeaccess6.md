#### Parser Content
```Java
{
Name = s-physical-badge-access-6
    Vendor = Badge
  Product = Badge
    Lms = Splunk
    DataType = "physical-access"
    TimeFormat = "MM/dd/yyyy HH:mm:ss"
    Conditions = ["AccessDescription","PersonnelID"]
    Fields = [
      """AccessFormatedTime"{1,20}:"{1,20}({time}\d\d/\d\d/\d\d\d\d \d\d:\d\d:\d\d)""",
      """AccesshostName":"({host}[^"]{1,2000})""",
      """PersonnelID":"({user}[^"]{1,2000})""",
      """PersonName":"({user_fullname}[^"]{1,2000})""",
      """PersonID":"({employee_id}[^"]{1,2000})""",
      """AccessDescription":"({outcome}[^"]{1,2000})""",
      """ReaderName":"({location_city}\w+)""",
      """ReaderName":"({location_door}[^"]{1,2000})"""
    ]
  }
```