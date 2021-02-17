#### Parser Content
```Java
{
Name = s-adaxes-app-activity
  Vendor = Adaxes 
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [""" ADAXES """]
  Fields = [
  
   """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d.\d+)""",
   """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
   """\s\d\d\:\d\d\:\d\d\s+({host}[\w.\-]+)\s+\S+\s+\S+\s+\d\d\:\d\d\:\d\d\s+({app}[^\s]+)\s+({user_fullname}[^\|\(\)]+)(\s+\(({user}[^@\|]+)(@({domain}[^|]+))?\))?\|({activity}[^\(']+)\s*\(?'({object}.+?)'\)?(\s+[^\|]*?'({target}.+?)\s*')?[^\|]*\|({outcome}Success)?"""
  ]
}
```