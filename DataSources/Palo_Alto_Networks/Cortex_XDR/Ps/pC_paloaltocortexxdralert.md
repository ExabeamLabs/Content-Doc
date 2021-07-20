#### Parser Content
```Java
{
Name = palo-alto-cortex-xdr-alert
  Vendor = Palo Alto Networks
  Product = Cortex XDR
  Lms = Direct
  DataType = "alert"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  """,alert,""" , """,true,""" ]
  Fields = [
  """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
  """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
  """"{1,20}\["{1,20}({src_ip}[A-Fa-f\d:.]{1,2000}).+?"{1,20}\]"{1,20}
```