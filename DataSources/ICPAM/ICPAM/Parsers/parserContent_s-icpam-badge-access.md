#### Parser Content
```Java
{
Name = s-icpam-badge-access
    Vendor = ICPAM
  Product = ICPAM
    Lms = Splunk
    DataType = "physical-access"
    TimeFormat = "MM/dd/yyyy HH:mm:ss"
    Conditions = [ """[Connected Physical Access Manager]""", """Trigger:""" ]
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}\S+)""",
      """\w+\s+\d+\s+\d\d:\d\d:\d\d\s+({host}[^\s]+)""",
      """Time:\s*({time}\d+/\d+/\d\d\d\d \d\d:\d\d:\d\d)""",
      """Trigger:\s*({outcome}.+?)\s*(#012|Time)""",
      """Device:\s*({location_door}.+?)\s+(#012|Personnel)""",
      """Badge Id\s*:\s*({badge_id}\d+\s*\d+)""",
      """Personnel record:\s*({last_name}.+?)\s*,\s+({first_name}.+?)\s*(#012|Credential)"""
    ]
  }
```