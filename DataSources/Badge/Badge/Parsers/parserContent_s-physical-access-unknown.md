#### Parser Content
```Java
{
Name = s-physical-access-unknown
  Vendor = Badge
  Product = Badge
  Lms = Direct
  DataType = "physical-access"
  TimeFormat = "dd/MM/yyyy HH:mm:ss a"
  Conditions = [ """"Card Event"""", """"Door Access Granted"""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d{1,100}\/\d{1,100}\/\d\d\d\d\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(AM|PM|am|pm)),"Card Event","({outcome}[^"]{1,2000})","(({user}[^",\s]{1,2000})[^,]{0,2000}
```