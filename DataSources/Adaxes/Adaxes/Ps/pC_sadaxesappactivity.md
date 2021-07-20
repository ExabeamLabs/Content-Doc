#### Parser Content
```Java
{
Name = s-adaxes-app-activity
  Vendor = Adaxes
  Product = Adaxes
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [""" ADAXES """]
  Fields = [
  
   """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d.\d{1,100})""",
   """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
   """\s\d\d\:\d\d\:\d\d\s{1,100}({host}[\w.\-]{1,2000})\s{1,100}\S+\s{1,100}\S+\s{1,100}\d\d\:\d\d\:\d\d\s{1,100}({app}[^\s]{1,2000})\s{1,100}({user_fullname}[^\|\(\)]{1,2000})(\s{1,100}\(({user}[^@\|]{1,2000})(@({domain}[^|]{1,2000}))?\))?\|({activity}[^\(']{1,2000})\s{0,100}\(?'({object}.+?)'\)?(\s{1,100}[^\|]{0,2000}?'({target}.+?)\s{0,100}')?[^\|]{0,2000}\|({outcome}Success)?"""
  ]
}
```