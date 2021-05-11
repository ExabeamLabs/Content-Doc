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
        """cs6=({time}\d{1,100}-\d{1,100}-\d{1,100}\s\d{1,100}:\d{1,100}:\d{1,100}),(|({door_name}[^,]+)),(|({location_door}[^,]+)),(|({outcome}[^,]+)),(|({user}[^,]+)),(|({badge_id}\d{1,100})),(|({first_name}[^,]+)),(|({last_name}[^,]+)),[^,]*,[^,]+,(|({user_fullname}[^,]+)),(|None|({employee_type}[^,]+)),("{1,20})?(|({employee_title}[^,]+)),""",
        """cs6=\d{1,100}-\d{1,100}-\d{1,100}\s\d{1,100}:\d{1,100}:\d{1,100}
```