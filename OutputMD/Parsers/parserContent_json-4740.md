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
  Fields = [  """"TimeGenerated":"({time}[^"]*)""",
    """({event_name}A user account was locked out)""",
              """"MachineName":"({host}[^."]*)""",
              """"InstanceId":"({event_code}[^"]*)""",
              """"4":"({caller_user}[^"]*)""",
              """"5":"({caller_domain}[^"]*)""",
              """"6":"({logon_id}[^"]*)""",
              """"2":"({user_sid}[^"]*)""",
              """"0":"({user}[^"]*)""",
              """"1":"({src_host}[^"]*)""" 
           ]
        DupFields = [ "host->dest_host",
                      "caller_domain->domain"]
}
```