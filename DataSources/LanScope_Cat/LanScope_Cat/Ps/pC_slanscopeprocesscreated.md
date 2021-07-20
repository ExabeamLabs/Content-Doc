#### Parser Content
```Java
{
Name = s-lanscope-process-created
  Product = LanScope Cat
  DataType = "process-created"
  IsHVF = true
  Conditions = [ """"リアルタイムイベントログ"""", """"ACTIVE"""" ]
  Fields = ${LanScopeParserTemplates.s-lanscope-app-activity.Fields}[
    ""","{0,20}リアルタイムイベントログ"{0,20}
s-lanscope-app-activity = {
  Vendor = LanScope
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    ""","{0,20}(|({host}[^"]{1,2000}))"{0,20},"{0,20}(|({user}[^"]{1,2000}))"{0,20},"{0,20}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"{0,20},"{0,20}[^"]{0,2000}"{0,20},"{0,20}(|({activity}[^"]{1,2000}))"{0,20},("{0,20}[^"]{0,2000}"{0,20},){2}"{0,20}(|({app}[^"]{1,2000}))"{0,20},("{0,20}[^"]{0,2000}"{0,20},){2}"{0,20}(|({file_path}({file_parent}[^"]{1,2000}?[\\\/]{1,2000})?({file_name}[^"\\\/]{1,2000}?(\.({file_ext}\w+))?)))"{0,20},"{0,20}[^"]{0,2000}"{0,20},"{0,20}(|({bytes_num}\d{1,100})({bytes_unit}\w+))"{0,20},"""
  ]

```