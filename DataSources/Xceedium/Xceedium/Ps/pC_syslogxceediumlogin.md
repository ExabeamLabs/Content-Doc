#### Parser Content
```Java
{
Name = syslog-xceedium-login
  Vendor = Xceedium
  Product = Xceedium
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  """Message 18019:""", """logged in successfully""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[^\s]{1,2000})""",
    """"{1,20}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"{1,20}\s{0,100}
```