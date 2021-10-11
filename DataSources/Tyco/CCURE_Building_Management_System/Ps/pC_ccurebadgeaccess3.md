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
        """exabeam_host=({host}[^\s]{1,2000})""",
        """cs6=({time}\d{1,100}-\d{1,100}-\d{1,100}\s\d{1,100}:\d{1,100}:\d{1,100}),(|({door_name}[^,]{1,2000})),(|({location_door}[^,]{1,2000})),(|({outcome}[^,]{1,2000})),(|({user}[^,]{1,2000})),(|({badge_id}\d{1,100})),(|({first_name}[^,]{1,2000})),(|({last_name}[^,]{1,2000})),[^,]{0,2000},[^,]{1,2000},(|({user_fullname}[^,]{1,2000})),(|None|({employee_type}[^,]{1,2000})),("{1,20})?(|({employee_title}[^,]{1,2000})),""",
        """cs6=\d{1,100}-\d{1,100}-\d{1,100}\s\d{1,100}:\d{1,100}:\d{1,100},([^,]{1,2000},){12}(.+?"{1,20},)?(|({user_email}[^,]{1,2000})),(|({department}[^,]{1,2000})),(|({employee_status}[^,]{1,2000})),"""

  ]
}
```