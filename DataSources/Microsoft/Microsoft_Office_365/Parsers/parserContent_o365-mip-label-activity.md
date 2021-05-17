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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"{0,20}CreationTime"{0,20}:\s{0,100}"{0,20}({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})"{0,20}""",
    """Workload"{0,20}:\s{0,100}"{0,20}({app}[^"]{1,2000})"""",
    """ObjectId"{0,20}:\s{0,100}"{0,20}<?({object}[^"]{1,2000}?)>?"""",
    """Operation"{0,20}:\s{0,100}"{0,20}({activity}[^"]{1,2000})"{0,20}""",
    """UserId"{0,20}:\s{0,100}"{0,20}({user_email}[^@]{1,2000}@({email_domain}[^"]{1,2000}))"{0,20}""",
    """Sender"{0,20}:\s{0,100}"{0,20}({sender}[^"]{1,2000})"""",
    """Receivers"{0,20}:\s{0,100}\["{0,20}({recipient}[^"]{1,2000})"""
    ]
    DupFields = [ "sender->user_email", "recipient->recipients" ]
}
```