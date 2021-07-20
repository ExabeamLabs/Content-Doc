#### Parser Content
```Java
{
Name = cef-xps-print-activity-1
  Vendor = XPS
  Product = XPS
  Lms = Splunk
  DataType = "print-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """printer=""", """type=""", """operation=""", """attributes=""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """printer=({printer_name}[^=]{1,2000}?)\s{0,100}\w+=""",
    """type=({object}[^=]{1,2000}?)\s{0,100}\w+=""",
    """attributes=({bytes}\d{1,200})\s{0,100}\w+=""",
    """operation=({activity}[^=]{1,2000}?)\s{0,100}\w+=""",
    ]
    DupFields = [ "printer_name->dest_host" ]
}
```