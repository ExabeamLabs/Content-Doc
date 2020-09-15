#### Parser Content
```Java
{
Name = rs2-physical-access
  Vendor = RS2
  Product = RS2
  Lms = Direct
  DataType = "physical-access"
  TimeFormat = "yyyy.MM.dd.HH.mm.ss.SSS"
  Conditions = [ """||RS2||""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """({time}\d\d\d\d\.\d\d\.\d\d\.\d\d\.\d\d\.\d\d\.\d{3})\d*\|\|[^\|]*\|\|(|({user_fullname}[^\|]+))\|\|([^\|]*\|\|){3}(|({location_full}[^\|]+))\|\|(|({outcome}[^\|\-]+)(-({failure_reason}[^\|\-]+))?)\|\|(|({badge_id}[^\|]+))\|\|[^\|]*\|\|(|({user}[^\|]+))\|\|""",
  ]
}
```