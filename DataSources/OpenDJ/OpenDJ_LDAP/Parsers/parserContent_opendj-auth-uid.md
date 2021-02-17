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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\[({time}\d\d\/\w+\/\d\d\d\d:\d\d:\d\d:\d\d [-\+]\d+)\]""",
    """conn=({conn_id}\d+)""",
    """uid=({user_uid}\d+)"""
  ]
}
```