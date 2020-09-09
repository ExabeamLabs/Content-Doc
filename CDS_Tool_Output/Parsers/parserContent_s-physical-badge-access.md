#### Parser Content
```Java
{
Name = s-physical-badge-access-5
    Vendor = Unknown
    Lms = Splunk
    DataType = "physical-access"
    TimeFormat = "epoch_sec"
    Conditions = ["BADGE", "exabeam_raw"]
    Fields = [
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """exabeam_host=({host}[^\s]+)""",
      """(?:([^\|]*\|))\s+({time}\d+)""",
      """(?:([^\|]*\|)){3}\s+({last_name}[^,\|]+),\s+({first_name}[^\|]+)\s+\|""",
      """(?:([^\|]*\|)){4}\s+({outcome}[^\|]+)\s+\|""",
      """(?:([^\|]*\|)){5}\s+\d+\s+-\s*({location_city}[^-]+)\s+-({location_door}[^\|]+)\s+\|""",
      """(?:([^\|]*\|)){6}\s+({location_building}.+?)\s+$"""
    ]
  }
```