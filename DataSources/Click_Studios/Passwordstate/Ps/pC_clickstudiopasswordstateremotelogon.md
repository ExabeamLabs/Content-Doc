#### Parser Content
```Java
{
Name = clickstudio-passwordstate-remote-logon
  Vendor = Click Studios
  Product = Passwordstate
  Lms = Splunk
  DataType = "remote-logon"
  TimeFormat = "dd-mm-yyy HH:mm:ss"
  Conditions = [ """Passwordstate:""", """initiated a Remote Session connection""", """PasswordID =""" ]
  Fields = [
    """({time}\d{2}-\d{2}-\d{4}\s\d{2}:\d{2}:\d{2})\s""",
    """IP Address\s{1,100}=\s{1,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\d\d:\d\d:\d\d\s({host}[\w\-.]{1,2000})\s{1,100}""",
    """Passwordstate:\s({user_fullname}[^\(]{1,2000}?)\s\((({domain}[^\\\)\s]{1,2000})\\{1,20})?({user}[^\)\s]{1,2000})\)""",
    """({event_name}initiated a Remote Session connection)"""
   ]


}
```