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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """({time}\d\d\d\d\.\d\d\.\d\d\.\d\d\.\d\d\.\d\d\.\d{3})\d{0,100}\|\|[^\|]{0,2000}\|\|(|({user_fullname}[^\|]{1,2000}))\|\|([^\|]{0,2000}\|\|){3}(|({location_full}[^\|]{1,2000}))\|\|(|({outcome}[^\|\-]{1,2000})(-({failure_reason}[^\|\-]{1,2000}))?)\|\|(|({badge_id}[^\|]{1,2000}))\|\|[^\|]{0,2000}\|\|(|({user}[^\|]{1,2000}))\|\|""",
  ]
}
```