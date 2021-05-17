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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """("\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d",)"({time}\d{4}-\d\d-\d\d \d\d:\d\d:\d\d.\d\d\d)",""",
    """("\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d",){2}("[^"]{0,2000}",){21}"({user}[^"]{1,2000})"""",
    """("\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d",){2}("[^"]{0,2000}",){52}"({file_name}[^"]{1,2000})"""",
    """("\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d",){2}("[^"]{0,2000}",){14}"({printer_name}[^"]{1,2000})""",
    """("\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d",){2}("[^"]{0,2000}",){15}"({number_of_page}[^"]{1,2000})""",
    """("\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d",){2}("[^"]{0,2000}",){3}"({asset_id}[^"]{1,2000})"""",
  ]
}
```