#### Parser Content
```Java
{
Name = s-icpam-badge-access
    Vendor = ICPAM
    Lms = Splunk
    DataType = "physical-access"
    TimeFormat = "MM/dd/yyyy HH:mm:ss"
    Conditions = [ """[Connected Physical Access Manager]""", """Trigger:""" ]
    Fields = [
      """\w+\s+\d+\s+\d\d:\d\d:\d\d\s+({host}[^\s]+)""",
      """Time:\s*({time}\d+/\d+/\d\d\d\d \d\d:\d\d:\d\d)""",
      """Trigger:\s*({outcome}.+?)#012""",
      """Device:\s*({location_door}.+?)#012""",
      """Badge Id\s*:\s*({badge_id}\d+\s*\d+)""",
      """Personnel record:\s*({last_name}[^,]+),\s*({first_name}.+?)#012"""
    ]
  }
```