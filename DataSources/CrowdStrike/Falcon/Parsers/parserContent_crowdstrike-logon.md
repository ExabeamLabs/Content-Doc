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
      """exabeam_host=([^=]+@\s{0,100})?({host}[\w\-.]+)""",
      """"aip":"({aip}[^"]+)""",
      """suser=((?i)system|({user}[^\s]+))""",
      """suid=({sid}[^\s]+)""", 
      """"AuthenticationPackage":"({auth_package}[^"]+)""",
      """"timestamp":"({time}\d{1,100})""",
      """"LogonType":"({logon_type}\d{1,100})""",
      """"UserName":"((?i)system|({user}[^"]+))""",
      """"LogonServer":"({auth_server}[^"]+)"""
      """"UserName":"({dest_host}[^"$]+)\$""",
      """"ClientComputerName\\?"{1,20}:\\?"{1,20}(-|({dest_host}[^"\\,]+))""",
      """"UserPrincipal":"({user_email}[^"]+)""",
      """"UserSid":"({user_sid}[^"]+)""",
      """"aid":"({aid}[^"]+)""",
      """"event_simpleName":"({event_code}[^"]+)""",
      """"LogonDomain":"(NT AUTHORITY|({domain}[^"]+))""",
    ]
    DupFields = ["user->account"]
  }
```