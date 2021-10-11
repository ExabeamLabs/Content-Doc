#### Parser Content
```Java
{
Name = checkpoint-failed-vpn-login
  Vendor = Check Point Software
  Product = Check Point Security Gateway
  Lms = Direct
  TimeFormat = "ddMMMyyyy,HH:mm:ss"
  DataType = "failed-vpn-login"
  Conditions = [ """,alert,reject,""" ]
  Fields = [
    """({time}\d{1,100}\w+\d\d\d\d,\d{1,100}:\d{1,100}:\d{1,100})(\s{1,100}(\+|\-)\d{1,100})?,(|({host}[^,]{1,2000})),alert,reject,([^,]{0,2000}
```