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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """("\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d",)"({time}\d{4}-\d\d-\d\d \d\d:\d\d:\d\d.\d\d\d)",""",
    """("\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d",){2}("[^"]{0,2000}",){21}"({user}[^"]{1,2000})"""",
    """("\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d",){2}("[^"]{0,2000}",){10}"({process_name}[^"]{1,2000})"""",
    """("\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d",){2}("[^"]{0,2000}",){3}"({asset_id}[^"]{1,2000})"""",
  ]
}
```