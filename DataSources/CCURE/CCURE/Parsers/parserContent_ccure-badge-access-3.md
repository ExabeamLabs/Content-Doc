#### Parser Content
```Java
{
Name = ccure-badge-access-3
  Vendor = CCURE
  Product = CCURE
  Lms = Syslog
  DataType = "physical-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = ["""<custom condition CONT-9359>""" ]
  Fields = [
        """exabeam_host=({host}[^\s]+)""",
        """({time}\d+-\d+-\d+\s\d+:\d+:\d+),(|({door_name}[^,]+)),(|({location_door}[^,]+)),(|({outcome}[^,]+)),(|({user}[^,]+)),(|({badge_id}\d+)),(|({first_name}[^,]+)),(|({last_name}[^,]+)),[^,]*,[^,]+,(|({user_fullname}[^,]+)),(|None|({employee_type}[^,]+)),("+)?(|({employee_title}[^,]+)),""",
        """\d+-\d+-\d+\s\d+:\d+:\d+,([^,]+,){12}(.+?"+,)?(|({user_email}[^,]+)),(|({department}[^,]+)),(|({employee_status}[^,]+)),"""

  ]
}
```