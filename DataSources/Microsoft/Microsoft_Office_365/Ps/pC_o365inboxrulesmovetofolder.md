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
    """MoveToFolder",.+?Value":"({target}[^\s"]{1,2000})""""
    """"ResultStatus":"({outcome}[^"]{1,2000})"""",
    """"ClientIP":"({src_ip}[^:]{1,2000}):""",
    """({activity}MoveToFolder)"""",
    """msg=({additional_info}.+?)\srequest=""",
    """UserId":"({user_email}[^"\\]{1,2000}@({user_domain}[^"]{1,2000}))""",
    """destinationServiceName =({app}.+?)\sdevice""",
    """UserId":"(\\.+)?\/({user_fullname}[^,\\"]{1,2000})\\"\s{0,100}on behalf""",
    """UserId":"(\\.+)?\/({user_lastname}[^,]{1,2000}),\s{0,100}({user_firstname}[^\\"]{1,2000})\\"\s{0,100}on behalf"""
    """"SubjectOrBodyContainsWords":"({filter_key_words}[^"]{1,2000})"""
  ]
  DupFields = ["user_domain->email_domain"]


}
```