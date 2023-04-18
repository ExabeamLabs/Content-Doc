#### Parser Content
```Java
{
Name = exchange-app-login-1
  Vendor = Microsoft
  Product = Exchange
  Lms = Syslog
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """Exchange Server""", """,authenticated""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)(,[^,]{0,2000}){3

}
```