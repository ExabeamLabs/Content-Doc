#### Parser Content
```Java
{
Name = genetec-badge-access
  Vendor = Genetec
  Product = Genetec
  Lms = Direct
  DataType = "physical-access"
  TimeFormat = "M/d/yyyy H:mm:ss a"
  Conditions = [ """<custom_condition_cont-7473>""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """({outcome}[^,="]+),(|({location_door}[^,]+)),[^,]*,(|({first_name}[^,]+)),(|({last_name}[^,]+)),(|({badge_id}[^,]+)),({time}\d+/\d+/\d\d\d\d \d+:\d+:\d+ (am|AM|pm|PM))"""
  ]
}
```