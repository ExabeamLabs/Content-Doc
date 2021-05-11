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
    """^([^\,]*\,){7}({time}\d{1,100}\/\d{1,100}\/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100})""",
    """^([^\,]*\,){5}(SYSTEM|NETWORK SERVICE|({user}[^\,]+))\,""",
    """({host}[\w\-.]+),\d{1,100}
```