#### Parser Content
```Java
{
Name = absolute-app-login
  Vendor = Absolute
  Product = Absolute SIEM Connector
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss z"
  Conditions = [ """AbsoluteSIEMConnector""", """eventType="UserLogin"""", """actorType="User"""", """actorName =""", """verb="LoggedIn"""" ]
  Fields = [
    """date="({time}\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\s\w{3})""",
    """\s({host}[\w\-.]{1,2000})\sAbsoluteSIEMConnector""",
    """({event_name}LoggedIn)""",
    """({activity}UserLogin)""",
    """actorName ="(({user_email}[^"@]{1,2000}@[^".]{1,2000}\.[^"]{1,2000})|({user}[^"\s]{1,2000}))""",
    """objectProperties="({additional_info}.{1,2000}?)"\s{1,100}\w{1,100}="""
   ]


}
```