#### Parser Content
```Java
{
Name = ccure-badge-access-3
  Vendor = Tyco
  Product = CCURE Building Management System
  Lms = Syslog
  DataType = "physical-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """requestClientApplication=CCure""", """|Skyformation|""", """cs6=""" ]
  Fields = [
        """exabeam_host=({host}[^\s]+)""",
        """\s+({host}[^\s]+)\s+Skyformation - """,
        """cs6=({time}\d+-\d+-\d+\s\d+:\d+:\d+),(|({door_name}[^,]+)),(|({location_door}[^,]+)),(|({outcome}[^,]+)),(|({user}[^,]+)),(|({badge_id}\d+)),(|({first_name}[^,]+)),(|({last_name}[^,]+)),[^,]*,[^,]+,(|({user_fullname}[^,]+)),(|None|({employee_type}[^,]+)),("+)?(|({employee_title}[^,]+)),""",
        """cs6=\d+-\d+-\d+\s\d+:\d+:\d+,([^,]+,){12}(.+?"+,)?(|({user_email}[^,]+)),(|({department}[^,]+)),(|({employee_status}[^,]+)),"""

  ]
}
```