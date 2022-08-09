#### Parser Content
```Java
{
Name = wiz-app-login
 Vendor = Wiz
 Product = Wiz
 Lms = Splunk
 DataType = "app-login"
 TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
 Conditions = [ """,Login,""", """"name": "federated-authenticate"""", """"name": "login"""", """,SUCCESS""" ]
 Fields = [
   """ACCOUNT,({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,6}Z)""",
   """({event_name}Login)""",
   """"user_name":\s{0,100}"(({user_email}[^@]{1,2000}@[^\s"]{1,2000}?)|({user}[^\s]{1,2000}?))"""",
   """\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.[^,]{1,2000

}
```