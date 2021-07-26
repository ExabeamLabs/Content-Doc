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
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
      """\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d\s{1,100}({host}[^\s]{1,2000})""",
      """Time:\s{0,100}({time}\d{1,100}/\d{1,100}/\d\d\d\d \d\d:\d\d:\d\d)""",
      """Trigger:\s{0,100}({outcome}.+?)\s{0,100}(#012|Time)""",
      """Device:\s{0,100}({location_door}.+?)\s{1,100}(#012|Personnel)""",
      """Badge Id\s{0,100}:\s{0,100}({badge_id}\d{1,100}\s{0,100}\d{1,100})""",
      """Personnel record:\s{0,100}({last_name}.+?)\s{0,100}
```