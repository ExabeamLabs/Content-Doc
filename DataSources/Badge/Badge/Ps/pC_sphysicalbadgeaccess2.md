#### Parser Content
```Java
{
Name = s-physical-badge-access-2
    Vendor = Badge
  Product = Badge
    Lms = Splunk
    DataType = "physical-access"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ " CardAdmitted ", "exabeam_raw"]
    Fields = [
      """exabeam_raw=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """exabeam_host=({host}[^\s]{1,2000})""",
      """exabeam_raw=[^\s]{1,2000}\s{1,100}[^\s]{1,2000}\s{1,100}\d{1,100}\s{1,100}({employee_id}\d{1,100})\s{1,100}({user}[^\s]{1,2000})\s{1,100}({location_door}.+?)\s{1,100}({badge_id}\d{1,100})\s{1,100}""",
      """exabeam_raw=[^\s]{1,2000}\s{1,100}[^\s]{1,2000}\s{1,100}\d{1,100}\s{1,100}\d{1,100}\s{1,100}[^\s]{1,2000}\s{1,100}({location_building}[^\s]{1,2000})\s{1,100}""",
      """exabeam_raw=[^\s]{1,2000}\s{1,100}[^\s]{1,2000}\s{1,100}\d{1,100}\s{1,100}\d{1,100}\s{1,100}[^\s]{1,2000}\s{1,100}[^\s]{1,2000}\s{1,100}({location_city}.+?)\s{1,100}\w+-\w+""",
      """({outcome}CardAdmitted)"""
    ]
  }
```