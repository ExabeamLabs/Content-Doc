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
      """exabeam_host=({host}[^\s]+)""",
      """(?:([^\|]*\|))\s{1,100}({time}\d{1,100})""",
      """(?:([^\|]*\|)){3}\s{1,100}({last_name}[^,\|]+),\s{1,100}({first_name}[^\|]+)\s{1,100}\|""",
      """(?:([^\|]*\|)){4}\s{1,100}({outcome}[^\|]+)\s{1,100}\|""",
      """(?:([^\|]*\|)){5}\s{1,100}\d{1,100}\s{1,100}-\s{0,100}({location_city}[^-]+)\s{1,100}-({location_door}[^\|]+)\s{1,100}\|""",
      """(?:([^\|]*\|)){6}\s{1,100}({location_building}.+?)\s{1,100}$"""
    ]
  }
```