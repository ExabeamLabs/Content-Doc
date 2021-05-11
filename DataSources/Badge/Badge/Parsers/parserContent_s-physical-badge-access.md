#### Parser Content
```Java
{
Name = s-physical-badge-access
    Vendor = Badge
  Product = Badge
    Lms = Splunk
    DataType = "physical-access"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ "Badge_ID", "Access_Event", "Reader_Description", "exabeam_raw"]
    Fields = [
      """exabeam_raw="{1,20}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """exabeam_host=({host}[^\s]+)""",
      """Badge_ID=({badge_id}\d{1,100})""",
      """First_Name="{1,20}({first_name}[^"]+)""",
      """Last_Name="{1,20}({last_name}[^"]+)""",
      """Access_Event="{1,20}({outcome}[^"]+)""",
      """Reader_Description="{1,20}({location_building}[^-\s]+)""",
      """Reader_Description="{1,20}({location_door}[^"]+)""",
      """Location="{1,20}({location_city}[^"]+)"""
    ]
  }
```