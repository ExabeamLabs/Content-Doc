#### Parser Content
```Java
{
Name = json-4740
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-account-lockout"
  TimeFormat = "MM/dd/yyyy H:mm:ss a"
  Conditions = [ """"InstanceId":"4740"""" ]
  Fields = [  """"TimeGenerated":"({time}[^"]{0,2000})""",
    """({event_name}A user account was locked out)""",
              """"MachineName":"({host}[^."]{0,2000})""",
              """"InstanceId":"({event_code}[^"]{0,2000})""",
              """"4":"({caller_user}[^"]{0,2000})""",
              """"5":"({caller_domain}[^"]{0,2000})""",
              """"6":"({logon_id}[^"]{0,2000})""",
              """"2":"({user_sid}[^"]{0,2000})""",
              """"0":"({user}[^"]{0,2000})""",
              """"1":"({src_host}[^"]{0,2000})""" 
           ]
        DupFields = [ "host->dest_host",
                      "caller_domain->domain"]
}
```