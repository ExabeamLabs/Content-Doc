#### Parser Content
```Java
{
Name = s-lanscope-web-activity
  Vendor = LanScope
  Product = LanScope Cat
  Lms = Splunk
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """"Webアクセスログ"""" ]
  Fields = [
    ""","{0,20}(|({host}[^"]{1,2000}))"{0,20}
```