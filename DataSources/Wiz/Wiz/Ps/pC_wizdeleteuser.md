#### Parser Content
```Java
{
Name = wiz-delete-user
 Vendor = Wiz
 Product = Wiz
 Lms = Splunk
 DataType = "account-deleted"
 TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
 Conditions = [ """,DeleteUser,""", """,USER_ACCOUNT,""", """,SUCCESS""" ]
 Fields = [
   """ACCOUNT,({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,6}Z)""",
   """({event_name}DeleteUser)""",
   """DeleteUser,[^}]{1,2000}?"id"{1,20}:[^}]{1,2000}\|({target_user_email}[^@]{1,2000}@[^\s"]{1,2000}?)"{1,20}\}""",
   """,({user_email}[^@\s\|]{1,2000}@[^\s"]{1,2000}?),USER_ACCOUNT""",
   """\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.[^,]{1,2000

}
```