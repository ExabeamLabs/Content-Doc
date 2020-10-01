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
      """exabeam_host=({host}[^\s]+)""",
      """exabeam_raw=[^\s]+\s+[^\s]+\s+\d+\s+({employee_id}\d+)\s+({user}[^\s]+)\s+({location_door}.+?)\s+({badge_id}\d+)\s+""",
      """exabeam_raw=[^\s]+\s+[^\s]+\s+\d+\s+\d+\s+[^\s]+\s+({location_building}[^\s]+)\s+""",
      """exabeam_raw=[^\s]+\s+[^\s]+\s+\d+\s+\d+\s+[^\s]+\s+[^\s]+\s+({location_city}.+?)\s+\w+-\w+""",
      """({outcome}CardAdmitted)"""
    ]
  }
```