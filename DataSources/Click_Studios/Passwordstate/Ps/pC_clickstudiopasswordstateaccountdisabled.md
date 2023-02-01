#### Parser Content
```Java
{
Name = clickstudio-passwordstate-account-disabled
  Vendor = Click Studios
  Product = Passwordstate
  Lms = Splunk
  DataType = "account-disabled"
  TimeFormat = "dd-mm-yyy HH:mm:ss"
  Conditions = [ """Passwordstate:""", """Passwordstate Windows Service disabled the User Account""" ]
  Fields = [
    """({time}\d{2}-\d{2}-\d{4}\s\d{2}:\d{2}:\d{2})\s""",
    """IP Address\s{1,100}=\s{1,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\d\d:\d\d:\d\d\s({host}[\w\-.]{1,2000})\s{1,100}""",
    """({event_name}Passwordstate Windows Service disabled the User Account)"""
   ]


}
```