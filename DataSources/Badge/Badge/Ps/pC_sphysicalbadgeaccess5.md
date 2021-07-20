#### Parser Content
```Java
{
Name = s-physical-badge-access-5
    Vendor = Badge
  Product = Badge
    Lms = Splunk
    DataType = "physical-access"
    TimeFormat = "epoch_sec"
    Conditions = ["BADGE", "Floor"]
    Fields = [
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """exabeam_host=({host}[^\s]{1,2000})""",
      """(?:([^\|]{0,2000}\|))\s{1,100}({time}\d{1,100})""",
      """(?:([^\|]{0,2000}\|)){3}\s{1,100}({last_name}[^,\|]{1,2000}),\s{1,100}({first_name}[^\|]{1,2000})\s{1,100}\|""",
      """(?:([^\|]{0,2000}\|)){4}\s{1,100}({outcome}[^\|]{1,2000})\s{1,100}\|""",
      """(?:([^\|]{0,2000}\|)){5}\s{1,100}\d{1,100}\s{1,100}-\s{0,100}({location_city}[^-]{1,2000})\s{1,100}-({location_door}[^\|]{1,2000})\s{1,100}\|""",
      """(?:([^\|]{0,2000}\|)){6}\s{1,100}({location_building}.+?)\s{1,100}$"""
    ]
  }
```