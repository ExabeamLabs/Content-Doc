#### Parser Content
```Java
{
Name = o365-activity-1
  Vendor = Microsoft
  Product = Office 365
  Lms = Direct
  DataType = "o365-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """succeeded""", """><Channel>""", """MailboxPermission""" ]
  Fields = [
    """SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[^\s\<]+)""",
    """><Message>Cmdlet ({result}[^"\\\.]+)""",
    """<Channel>({app}.+?)<\/Channel>""",
    """AccessRights=\{({additional_info}.+?)\}\}</Data><Data>.+?({user_fullname}[^\\\/]+?)<\/Data>""",
    """, User=({object}[^,]+)""",
    """<Data>\{Identity=({resource}[^,]+)""",
    """<EventData><Data>({activity}.+?)<\/Data>""",
  ]
  DupFields = [ "result->outcome" ]
}
```