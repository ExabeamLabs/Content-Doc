#### Parser Content
```Java
{
Name = pmp-app-login
  Vendor = ManageEngine
  Product = Password Manager Pro
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [  """ User_Logged_in_-_SAML_Single_Sign_On """,""" Success """ ]
  Fields =  [
    """\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d\s{1,100}({host}[\w\-.]{1,2000})""",
    """\sSuccess\s[^\s]{1,2000}\s{1,100}(?:-)?({user}({user_firstname}[^:_]{1,2000})(_({user_lastname}[^:]{1,2000}))?):""",
    """({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """\s{1,100}(UserAudit:)?(System|N\/A|({user}({user_firstname}[^\s:_]{1,2000})(_({user_lastname}[^:\s]{1,2000}))?)):(?:({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^\s]{1,2000}))\s{1,100}({event_name}User_Logged_in_-_SAML_Single_Sign_On)""",
    """\w+ \d{1,100} \d\d:\d\d:\d\d\s{1,100}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
   ]


}
```