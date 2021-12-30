#### Parser Content
```Java
{
Name = azure-app-logon-3
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """"OperationName":"Sign-in activity"""", """destinationServiceName =Azure""" ]
  Fields = [
    """exabeam_host=([^=@]{1,2000}@\s{0,100})?({host}\S+)""",
    """"TIMEGENERATED":"({time}\d{4}-\d{1,2}-\d{1,2}\s\d\d:\d\d:\d\d.\d\d\d)"""",
    """"IPAddress":"({src_ip}[A-Fa-f:\d.]{1,2000})"""",
    """"UserPrincipalName":"({user_email}[^"\s@]{1,2000}@({email_domain}[^"\s@]{1,2000}))"""",
    """"ConditionalAccessStatus":"({outcome}[^"]{1,2000})"""",
    """\sdestinationServiceName =({app}[^=]{1,2000}?)\s{1,100}\w+=""",
    """"AppDisplayName":"({app}[^"]{1,200}?)\s{0,10}"""",
    """UserDisplayName"{1,20}:"{1,20}({user_fullname}[^"]{1,2000})""",
    """UserId"{1,20}:"{1,20}({user_id}[^"]{1,2000})""",
    """"{1,20}IPAddress"{1,20}:"{1,20}({src_ip}[^"]{1,2000})""",
    """"(Device)?(b|B)rowser":"({browser}[^"]{1,2000})""", 
    """"UserAgent\\*"{1,20}:\\*"{1,20}(,|({user_agent}[^"]{1,2000}))""",
    """"(Device)?(o|O)peratingSystem":"({os}[^"]{1,2000})""", 
    """"(F|f)ailureReason":"({failure_reason}.+?)(\.)?"""",
  ]


}
```