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
   """\s\d\d\:\d\d\:\d\d\s{1,100}({host}[\w.\-]+)\s{1,100}\S+\s{1,100}\S+\s{1,100}\d\d\:\d\d\:\d\d\s{1,100}({app}[^\s]+)\s{1,100}({user_fullname}[^\|\(\)]+)(\s{1,100}\(({user}[^@\|]+)(@({domain}[^|]+))?\))?\|({activity}[^\(']+)\s{0,100}\(?'({object}.+?)'\)?(\s{1,100}[^\|]*?'({target}.+?)\s{0,100}')?[^\|]*\|({outcome}Success)?"""
  ]
}
```