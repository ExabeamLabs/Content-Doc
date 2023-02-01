#### Parser Content
```Java
{
Name = clickstudio-passwordstate-account-password-reset-1
  Vendor = Click Studios
  Product = Passwordstate
  Lms = Splunk
  DataType = "account-password-reset"
  TimeFormat = "dd-mm-yyy HH:mm:ss"
  Conditions = [ """Passwordstate:""", """The Passwordstate Windows Service successfully reset the password for""", """PasswordID =""" ]
  Fields = [
    """({time}\d{2}-\d{2}-\d{4}\s\d{2}:\d{2}:\d{2})\s""",
    """IP Address\s{1,100}=\s{1,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\d\d:\d\d:\d\d\s({host}[\w\-.]{1,2000})\s{1,100}""",
    """({event_name}The Passwordstate Windows Service successfully reset the password)"""
   ]


}
```