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
      """exabeam_host=({host}[^\s]{1,2000})""",
      """Badge_ID=({badge_id}\d{1,100})""",
      """First_Name="{1,20}({first_name}[^"]{1,2000})""",
      """Last_Name="{1,20}({last_name}[^"]{1,2000})""",
      """Access_Event="{1,20}({outcome}[^"]{1,2000})""",
      """Reader_Description="{1,20}({location_building}[^-\s]{1,2000})""",
      """Reader_Description="{1,20}({location_door}[^"]{1,2000})""",
      """Location="{1,20}({location_city}[^"]{1,2000})"""
    ]
  }
```