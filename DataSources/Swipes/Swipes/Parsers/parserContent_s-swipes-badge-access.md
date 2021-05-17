#### Parser Content
```Java
{
Name = s-swipes-badge-access
    Vendor = Swipes
  Product = Swipes
    Lms = Splunk
    DataType = "physical-access"
    TimeFormat = "yyyy/MM/dd HH:mm:ss.SSS"
    Conditions = [ """exabeam_index=swipes""" ]
    Fields = [
      """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""",
      """exabeam_raw=([^\|]{0,2000}\|){4}({time}[^\|]{1,2000})\|""",
      """exabeam_raw=({department}[^\|]{1,2000})\|""",
      """exabeam_raw=([^\|]{0,2000}\|)({last_name}[^\|]{1,2000})\|""",
      """exabeam_raw=([^\|]{0,2000}\|){2}({first_name}[^\|]{1,2000})\|""",
      """exabeam_raw=([^\|]{0,2000}\|){5}({location_area}[^\|]{1,2000})\|""",
      """exabeam_raw=([^\|]{0,2000}\|){6}({location_door}[^\|]{1,2000})\|""",
      """exabeam_raw=([^\|]{0,2000}\|){7}({badge_id}[^\|]{1,2000})\|""",
    ]
    DupFields = ["location_area->location_building"]
  }
```