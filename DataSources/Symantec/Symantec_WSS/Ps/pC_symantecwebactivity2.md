#### Parser Content
```Java
{
Name = symantec-web-activity-2
  Vendor = Symantec
  Product = Symantec WSS
  Lms = Splunk
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """destinationServiceName =Symantec WSS""", """OBSERVED""", """http"""  ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """cs6=\[([^,]{1,2000

}
```