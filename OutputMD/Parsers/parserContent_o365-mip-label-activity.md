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
    """"*CreationTime"*:\s*"*({time}\d+-\d+-\d+T\d+:\d+:\d+)"*""",
    """Workload"*:\s*"*({app}[^"]+)"""",
    """ObjectId"*:\s*"*<?({object}[^"]+?)>?"""",
    """Operation"*:\s*"*({activity}[^"]+)"*""",
    """UserId"*:\s*"*({user_email}[^@]+@({email_domain}[^"]+))"*""",
    """Sender"*:\s*"*({sender}[^"]+)"""",
    """Receivers"*:\s*\["*({recipient}[^"]+)"""
    ]
    DupFields = [ "sender->user_email", "recipient->recipients" ]
}
```