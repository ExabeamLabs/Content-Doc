#### Parser Content
```Java
{
Name = o365-inbox-rules-move-to-folder
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""New-InboxRule""" , """MoveToFolder"""]
  Fields = [
    """"CreationTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""",
    """MoveToFolder",.+?Value":"({target}[^\s"]+)""""
    """"ResultStatus":"({outcome}[^"]+)"""",
    """"ClientIP":"({src_ip}[^:]+):""",
    """({activity}MoveToFolder)"""",
    """msg=({additional_info}.+?)\srequest=""",
    """UserId":"({user_email}[^"\\]+@({user_domain}[^"]+))""",
    """destinationServiceName=({app}.+?)\sdevice""",
    """UserId":"(\\.+)?\/({user_fullname}[^,\\"]+)\\"\s*on behalf""",
    """UserId":"(\\.+)?\/({user_lastname}[^,]+),\s*({user_firstname}[^\\"]+)\\"\s*on behalf"""
  ]
  DupFields = ["user_domain->email_domain"]
}
```