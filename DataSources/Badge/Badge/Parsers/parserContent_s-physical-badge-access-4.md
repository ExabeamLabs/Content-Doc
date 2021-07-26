#### Parser Content
```Java
{
Name = s-physical-badge-access-4
    Vendor = Badge
  Product = Badge
    Lms = Splunk
    DataType = "physical-access"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ "WorkerID=", "PrimarySeatLocation=", "exabeam_raw"]
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """exabeam_host=({host}[^\s]{1,2000})""",
      """WorkerID=({employee_id}\d{1,100})""",
      """FirstName=({first_name}.+?)\s{1,100}LastName=""",
      """LastName=({last_name}.+?)\s{1,100}WorkerID=""",
      """MessageType=({outcome}.+?)\s{1,100}Door=""",
      """Location="{1,20}({location_building}[^"]{1,2000})""",
      """Door="{1,20}({location_door}[^"]{1,2000})"""
    ]
  }
```