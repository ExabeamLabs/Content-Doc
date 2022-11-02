#### Parser Content
```Java
{
Name = absolute-app-activity
  Vendor = Absolute
  Product = Absolute SIEM Connector
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss z"
  Conditions = [ """AbsoluteSIEMConnector""", """eventType="DeviceUserInformationUpdated"""", """verb="Updated"""" ]
  Fields = [
    """date="({time}\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\s\w{3})""",
    """\s({host}[\w\-.]{1,2000})\sAbsoluteSIEMConnector""",
    """({activity}DeviceUserInformationUpdated)""",
    """objectID="({object}[^"]{1,2000})"""",
    """actorType=("Device".{1,2000}?actorName ="({src_host}[\w\-.]{1,2000})|"User".{1,2000}?actorName ="(({user_email}[^"@]{1,2000}@[^".]{1,2000}\.[^"]{1,2000})|({user}[^"\s]{1,2000})))"""",
    """objectProperties="({additional_info}.{1,2000}?)"\s{1,100}\w{1,100}="""
   ]
   DupFields = ["activity -> event_name"]


}
```