#### Parser Content
```Java
{
Name = liquidfiles-file-upload
  DataType = "file-upload"
  Conditions = [ """liquidfiles[""", """"message":"Binary Upload Complete"""" ]

liquidfiles-events = {
    Vendor = LiquidFiles
    Product = LiquidFiles
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Fields = [
      """"hostname":"({host}[^"]{1,2000})"""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """"filename":"({file_name}[^"]{1,2000}(\.)({file_ext}[^"]{1,2000}))"""",
      """"ip":"({src_ip}[A-Fa-f\d:.]{1,2000})"""",
      """"user_id":"(n/a|({user}[^"]{1,2000}?))"""",
      """"message":"({event_name}[^:"]{1,2000})""",
      """({app}liquidfiles)""",
      """"username":"(({user_email}[^@"]{1,2000}@[^\.]{1,2000}\.[^"]{1,2000})|({user}[^"]{1,2000}))"""",
    
}
```