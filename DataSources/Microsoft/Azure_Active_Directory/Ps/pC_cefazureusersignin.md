#### Parser Content
```Java
{
Name = cef-azure-user-signin
    Vendor = Microsoft
    Product = Azure Active Directory
    Lms = Direct
    DataType = "app-login"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """CEF:""", """destinationServiceName =Azure""", """"OperationName":"User Risk Detection"""", """"Activity":"signin"""", """"RiskDetail":"aiConfirmedSigninSafe"""" ]
    Fields = [
       """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)"""",
       """destinationServiceName =({app}Azure)""",
       """OperationName":"({activity}[^"]{1,2000})""",
       """({event_name}signin)""",
       """"IpAddress":"({src_ip}[a-fA-F\d.:]{1,2000})"""",
       """CallerIpAddress":"({src_ip}[a-fA-F\d.:]{1,2000})"""",
       """"UserPrincipalName":"({user_email}[^"\s@]{1,2000}@[^"\s@]{1,2000})""",
       """"UserDisplayName":"({user_fullname}({user_firstname}[^\s"]{1,2000})\s{1,20}({user_lastname}[^"]{1,2000}))""",
       """"userAgent\\?",\\"?Value\\?":\\?"({user_agent}[^"\\]{1,2000})\\?"""",
       """"RiskDetail":"({additional_info}[^"]{1,2000})""",
     ]


}
```