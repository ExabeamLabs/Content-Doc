#### Parser Content
```Java
{
Name = s-skysea-print-activity
  Vendor = SkySea
  Product = ClientView
  Lms = Splunk
  DataType = "print-activity"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ ",プリント," ]
  Fields = [
    """({host}[\w\-.]{1,2000}),\d{1,100}
```