#### Parser Content
```Java
{
Name = opendj-auth-uid
  Vendor = OpenDJ
  Product = OpenDJ LDAP
  Lms = Splunk
  DataType = "authentication-attempt"
  TimeFormat = "dd/MMM/yyyy:HH:mm:ss Z"
  Conditions = [ """uid=""", """ REQ conn=""", """op=""", """msgID=""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\[({time}\d\d\/\w+\/\d\d\d\d:\d\d:\d\d:\d\d [-\+]\d{1,100})\]""",
    """conn=({conn_id}\d{1,100})""",
    """uid=({user_uid}\d{1,100})"""
  ]
}
```