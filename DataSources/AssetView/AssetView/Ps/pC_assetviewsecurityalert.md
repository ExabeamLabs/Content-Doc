#### Parser Content
```Java
{
Name = assetview-security-alert
  Vendor = AssetView
  Product = AssetView
  Lms = Exabeam
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """使用禁止USB接続""", """35131""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """("\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d",)"({time}\d{4}-\d\d-\d\d \d\d:\d\d:\d\d.\d\d\d)",""",
    """("\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d",){2}("[^"]{0,2000}",){21}"({user}[^"]{1,2000})"""",
    """("\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d",){2}("[^"]{0,2000}",){54}"({vendor_id}[^"]{1,2000})""",
    """("\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d",){2}("[^"]{0,2000}",){56}"({usb_serial_number}[^"]{1,2000})""",
    """("\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d",){2}("[^"]{0,2000}",){58}"({usb_vendor}[^"]{1,2000})""",
    """("\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d",){2}("[^"]{0,2000}",){3}"({asset_id}[^"]{1,2000})"""",
  ]
}
```