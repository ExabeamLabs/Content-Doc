#### Parser Content
```Java
{
Name = s-pan-correlation-alert
  Vendor = Palo Alto Networks
  Product = WildFire
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,CORRELATION,"""]
  Fields = [
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """\d\d:\d\d:\d\d ({host}[\w\-.]{1,2000})""",
    """,CORRELATION,([^,]{0,2000}
```