#### Parser Content
```Java
{
Name = s-skysea-web-activity
  Vendor = SkySea
  Product = ClientView
  Lms = Splunk
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,Webアクセス,""" ]
  Fields = [
    """({host}[\w\-.]+),\d{1,100}
```