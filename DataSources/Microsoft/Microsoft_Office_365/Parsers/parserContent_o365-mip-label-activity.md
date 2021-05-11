#### Parser Content
```Java
{
Name = o365-mip-label-activity
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """Workload""", """"LabelName"""", """"LabelId""", """Operation""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """"{0,20}CreationTime"{0,20}:\s{0,100}"{0,20}({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})"{0,20}""",
    """Workload"{0,20}:\s{0,100}"{0,20}({app}[^"]+)"""",
    """ObjectId"{0,20}:\s{0,100}"{0,20}<?({object}[^"]+?)>?"""",
    """Operation"{0,20}:\s{0,100}"{0,20}({activity}[^"]+)"{0,20}""",
    """UserId"{0,20}:\s{0,100}"{0,20}({user_email}[^@]+@({email_domain}[^"]+))"{0,20}""",
    """Sender"{0,20}:\s{0,100}"{0,20}({sender}[^"]+)"""",
    """Receivers"{0,20}:\s{0,100}\["{0,20}({recipient}[^"]+)"""
    ]
    DupFields = [ "sender->user_email", "recipient->recipients" ]
}
```