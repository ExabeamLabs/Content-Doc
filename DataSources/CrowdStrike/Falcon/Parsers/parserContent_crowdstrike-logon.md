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
      """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
      """"aip":"({host}[^"]+)""",
      """suser=((?i)system|({user}[^\s]+))""",
      """suid=({sid}[^\s]+)""", 
      """"AuthenticationPackage":"({auth_package}[^"]+)""",
      """"timestamp":"({time}\d+)""",
      """"LogonType":"({logon_type}\d+)""",
      """"UserName":"((?i)system|({user}[^"]+))""",
      """"LogonServer":"({dest_host}[^"]+)"""
      """"UserName":"({dest_host}[^"$]+)\$""",
      """"UserPrincipal":"({user_email}[^"]+)""",
      """"UserSid":"({user_sid}[^"]+)""",
      """"aid":"({aid}[^"]+)""",
      """"event_simpleName":"({event_code}[^"]+)""",
      """"LogonDomain":"(NT AUTHORITY|({domain}[^"]+))""",
    ]
    DupFields = ["user->account"]
  }
```