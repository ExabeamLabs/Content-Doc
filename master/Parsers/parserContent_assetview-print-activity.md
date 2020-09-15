#### Parser Content
```Java
{
Name = assetview-print-activity
  Vendor = AssetView
  Product = AssetView
  Lms = Exabeam
  DataType = "print-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """印刷""", """15041""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """("\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d",)"({time}\d{4}-\d\d-\d\d \d\d:\d\d:\d\d.\d\d\d)",""",
    """("\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d",){2}("[^"]*",){21}"({user}[^"]+)"""",
    """("\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d",){2}("[^"]*",){52}"({file_name}[^"]+)"""",
    """("\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d",){2}("[^"]*",){14}"({printer_name}[^"]+)""",
    """("\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d",){2}("[^"]*",){15}"({number_of_page}[^"]+)""",
    """("\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d",){2}("[^"]*",){3}"({asset_id}[^"]+)"""",
  ]
}
```