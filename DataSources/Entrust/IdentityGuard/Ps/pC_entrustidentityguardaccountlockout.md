#### Parser Content
```Java
{
Name = entrust-identityguard-account-lockout
  Vendor = Entrust
  Product = IdentityGuard
  Lms = Direct
  DataType = "account-lockout"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ Maximum authentication attempts exceeded. """ , """ is locked.""" ]
  Fields = [
    """exabeam_time=({time}\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\[({time}\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)(\]|,\]|,\d{1,100}\])""",
    """({event_description}Maximum authentication.+?is locked.)""",
    """User (({user_email}[^\@\s]{1,2000}@[^\s]{1,2000})|(({domain}[^\\\/]{1,2000})[\\\/]{1,2000})?({user}[^\s]{1,2000})) is locked.""",
  ]
}
```