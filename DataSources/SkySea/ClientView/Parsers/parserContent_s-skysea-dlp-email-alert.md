#### Parser Content
```Java
{
Name = s-skysea-dlp-email-alert
  Vendor = SkySea
  Product = ClientView
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,メール,""" ]
  Fields = [
    """({host}[\w\-.]{1,2000}),\d{1,100}
```