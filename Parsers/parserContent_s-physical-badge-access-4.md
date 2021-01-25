#### Parser Content
```Java
{
Name = s-physical-badge-access-4
    Vendor = Unknown
    Lms = Splunk
    DataType = "physical-access"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ "WorkerID=", "PrimarySeatLocation=", "exabeam_raw"]
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """exabeam_host=({host}[^\s]+)""",
      """WorkerID=({employee_id}\d+)""",
      """FirstName=({first_name}.+?)\s+LastName=""",
      """LastName=({last_name}.+?)\s+WorkerID=""",
      """MessageType=({outcome}.+?)\s+Door=""",
      """Location="+({location_building}[^"]+)""",
      """Door="+({location_door}[^"]+)"""
    ]
  }
```