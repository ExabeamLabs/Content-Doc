#### Parser Content
```Java
{
Name = crowdstrike-logon
    Vendor = CrowdStrike
    Product = Falcon
    Lms = Direct
    DataType = "logon"
    TimeFormat = "epoch"
    Conditions = [ """"event_simpleName":"UserLogon"""", """"aid"""" ]
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
      """"aip":"({aip}[^"]{1,2000})""",
      """suser=((?i)system|({user}[^\s]{1,2000}))""",
      """suid=({sid}[^\s]{1,2000})""", 
      """"AuthenticationPackage":"({auth_package}[^"]{1,2000})""",
      """"timestamp":"({time}\d{1,100})""",
      """"LogonType":"({logon_type}\d{1,100})""",
      """"UserName":"((?i)system|({user}[^"]{1,2000}))""",
      """"LogonServer":"({auth_server}[^"]{1,2000})"""
      """"UserName":"({dest_host}[^"$]{1,2000})\$""",
      """"ClientComputerName\\?"{1,20}:\\?"{1,20}(-|({dest_host}[^"\\,]{1,2000}))""",
      """"UserPrincipal":"({user_email}[^@"]{1,2000}@[^."]{1,2000}\.[^"]{1,2000})"""",
      """"UserSid":"({user_sid}[^"]{1,2000})""",
      """"aid":"({aid}[^"]{1,2000})""",
      """"event_simpleName":"({event_code}[^"]{1,2000})""",
      """"LogonDomain":"(NT AUTHORITY|({domain}[^"]{1,2000}))""",
    ]
    DupFields = ["user->account"]
  

}
```