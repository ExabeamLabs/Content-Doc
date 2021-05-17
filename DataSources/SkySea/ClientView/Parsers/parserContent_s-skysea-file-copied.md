#### Parser Content
```Java
{
Name = s-skysea-file-copied
  Vendor = SkySea
  Product = ClientView
  Lms = Splunk
  DataType = "file-write"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ ",ファイル操作,", ",ファイルコピー," ]
  Fields = [
    """exabeam_raw=({host}[^\,]{1,2000})\,""",
    """(^|,)"?({host}[^,]{1,2000})"?,([^,]{0,2000}
```