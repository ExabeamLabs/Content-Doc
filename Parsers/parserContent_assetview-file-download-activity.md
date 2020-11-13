#### Parser Content
```Java
{
Name = assetview-file-download-activity
  Vendor = AssetView
  Product = AssetView
  Lms = Exabeam
  DataType = "file-download"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """WEBダウンロード""", """15091""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """("\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d",)"({time}\d{4}-\d\d-\d\d \d\d:\d\d:\d\d.\d\d\d)",""",
    """("\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d",){2}("[^"]*",){21}"({user}[^"]+)"""",
    """("\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d",){2}("[^"]*",){10}"({process_name}[^"]+)"""",
    """("\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d",){2}("[^"]*",){3}"({asset_id}[^"]+)"""",
  ]
}
```