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
      """exabeam_host=(.+?@\s*)?({host}[^\s]+)""",
      """exabeam_raw=([^\|]*\|){4}({time}[^\|]+)\|""",
      """exabeam_raw=({department}[^\|]+)\|""",
      """exabeam_raw=([^\|]*\|)({last_name}[^\|]+)\|""",
      """exabeam_raw=([^\|]*\|){2}({first_name}[^\|]+)\|""",
      """exabeam_raw=([^\|]*\|){5}({location_area}[^\|]+)\|""",
      """exabeam_raw=([^\|]*\|){6}({location_door}[^\|]+)\|""",
      """exabeam_raw=([^\|]*\|){7}({badge_id}[^\|]+)\|""",
    ]
    DupFields = ["location_area->location_building"]
  }
```