#### Parser Content
```Java
{
Name = assetview-usb-activity
  Vendor = AssetView
  Product = AssetView
  Lms = Exabeam
  DataType = "usb-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """ドライブ追加""", """15031""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """("\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d",)"({time}\d{4}-\d\d-\d\d \d\d:\d\d:\d\d.\d\d\d)",""",
    """("\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d",){2}("[^"]{0,2000}",){21}"({user}[^"]{1,2000})"""",
    """("\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d",){2}("[^"]{0,2000}",){17}"({drive_letter}[^"]{1,2000})""",
    """("\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d",){2}("[^"]{0,2000}",){54}"({vendor_id}[^"]{1,2000})""",
    """("\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d",){2}("[^"]{0,2000}",){56}"({usb_serial_number}[^"]{1,2000})""",
    """("\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d.\d\d\d",){2}("[^"]{0,2000}",){58}"({usb_vendor}[^"]{1,2000})""",
  ]
}
```