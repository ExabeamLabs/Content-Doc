#### Parser Content
```Java
{
Name = s-physical-badge-access
    Vendor = Unknown
    Lms = Splunk
    DataType = "physical-access"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ "Badge_ID", "Access_Event", "Reader_Description", "exabeam_raw"]
    Fields = [
      """exabeam_raw="+({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """exabeam_host=({host}[^\s]+)""",
      """Badge_ID=({badge_id}\d+)""",
      """First_Name="+({first_name}[^"]+)""",
      """Last_Name="+({last_name}[^"]+)""",
      """Access_Event="+({outcome}[^"]+)""",
      """Reader_Description="+({location_building}[^-\s]+)""",
      """Reader_Description="+({location_door}[^"]+)""",
      """Location="+({location_city}[^"]+)"""
    ]
  }
```