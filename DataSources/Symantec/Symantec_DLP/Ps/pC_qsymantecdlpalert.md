#### Parser Content
```Java
{
Name = q-symantec-dlp-alert
  Vendor = Symantec
  Product = Symantec DLP
  Lms = QRadar
  DataType = "dlp-alert"
  TimeFormat = "MMM dd, yyyy HH:mm:ss a"
  Conditions = [ """Symantec|DLP|""", """|policy=""", """|incidentSnapshot=""" ]
  Fields = [
    """exabeam_endTime=({time}\d{1,100})""",
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """\|occurredon=({time}\w+ \d{1,100}
```