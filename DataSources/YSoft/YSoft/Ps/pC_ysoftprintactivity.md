#### Parser Content
```Java
{
Name = ysoft-print-activity
  Vendor = YSoft
  Product = YSoft
  Lms = Direct
  DataType = "print-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """DeviceName ="""",""", PrinterLocation="""",""", PageCount="""" ]
  Fields = [
    """date="({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)""",
    """UserLogin="({user}[^"]{1,2000})"""",
    """DeviceName ="({printer_name}[^"]{1,2000})"""",
    """title="({object}[^"]{1,2000})"""",
    """PageCount="({num_pages}[^"]{1,2000})"""",
    """jobtype="({event_name}[^"]{1,2000})"""",
  ]


}
```