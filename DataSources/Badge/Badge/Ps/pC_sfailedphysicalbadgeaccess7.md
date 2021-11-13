#### Parser Content
```Java
{
Name = s-failed-physical-badge-access-7
    Vendor = Badge
  Product = Badge
    Lms = Splunk
    DataType = "failed-physical-access"
    TimeFormat = "yyyy-MM-dd HH:mm:ss a"
    Conditions = [",Card Rejected,", "exabeam_raw"]
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\d \d{1,100}:\d{1,100}:\d{1,100} (am|AM|PM|pm))""",
      """exabeam_host=({host}[^\s]{1,2000})""",
      """exabeam_raw=({last_name}[^,]{1,2000}),\s{1,100}({first_name}[^,]{1,2000}),""",
      """exabeam_raw=([^,]{0,2000

}
```