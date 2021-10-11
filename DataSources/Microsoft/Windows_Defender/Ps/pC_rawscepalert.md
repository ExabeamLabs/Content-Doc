#### Parser Content
```Java
{
Name = raw-scep-alert
  Vendor = Microsoft
  Product = Windows Defender
  Lms = Direct
  DataType = "alert"
  TimeFormat = "EEE MMM dd HH:mm:ss yyyy"
  Conditions = [ "Microsoft Antimalware", "Detection Origin" ]
  Fields = [
    """,({time}\w+ \w+ \d{1,100} \d\d:\d\d:\d\d \d{1,100}),""",
    """exabeam_source=({host}[\w.\-]{1,2000})""",
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""",
    """(?:([^",]{0,2000}
```