#### Parser Content
```Java
{
Name = s-lumension-usb
  Vendor = Lumension
  Product = Lumension
  Lms = Splunk
  DataType = "usb-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "raw_event_id" , "raw_g_hostname" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """\sraw_g_hostname="{1,20}({dest_host}[^"]{1,2000})"{1,20}
```