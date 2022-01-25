#### Parser Content
```Java
{
Name = s-skysea-file-operations
  Vendor = SkySea
  Product = ClientView
  Lms = Splunk
  DataType = "file-operations"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ ",ファイル操作," ]
  Fields = [
    """^([^\,]{0,2000}\,){7}({time}\d{1,100}\/\d{1,100}\/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100})""",
    """^([^\,]{0,2000}\,){5}(SYSTEM|NETWORK SERVICE|({user}[^\,]{1,2000}))\,""",
    """({host}[\w\-.]{1,2000}),\d{1,100}
```