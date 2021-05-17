#### Parser Content
```Java
{
Name = o365-activity-1
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Direct
  DataType = "o365-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """succeeded""", """><Channel>""", """MailboxPermission""" ]
  Fields = [
    """SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[^\s\<]{1,2000})""",
    """><Message>Cmdlet ({result}[^"\\\.]{1,2000})""",
    """<Channel>({app}.+?)<\/Channel>""",
    """AccessRights=\{({additional_info}.+?)\}\}</Data><Data>.+?({user_fullname}[^\\\/]{1,2000}?)<\/Data>""",
    """, User=({object}[^,]{1,2000})""",
    """<Data>\{Identity=({resource}[^,]{1,2000})""",
    """<EventData><Data>({activity}.+?)<\/Data>""",
    """User=(({domain}[^\\]{1,2000})\\)?({user}[^\s,]{1,2000})""", 
  ]
  DupFields = [ "result->outcome" ]
}
```