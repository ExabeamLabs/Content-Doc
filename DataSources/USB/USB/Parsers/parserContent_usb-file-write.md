#### Parser Content
```Java
{
Name = usb-file-write
  Vendor = USB
  Product = USB
  Lms = Splunk
  DataType = "usb-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """cs:usb:activity""", """"USB\""" ]
  Fields = [
    """exabeam_host=({host}[^,\s]{1,2000})""",
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """({device_id}USB[^"]{1,2000})",\d{1,100}
```