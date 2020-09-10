#### Parser Content
```Java
{
Name = json-4724
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-password-reset"
  TimeFormat = "MM/dd/yyyy H:mm:ss a"
  Conditions = [ """"InstanceId":"4724"""" ]
  Fields = [
    """({event_name}An attempt was made to reset an account's password)""",
        """"MachineName":"({host}[^."]+)""",
              """"TimeGenerated":"({time}[^"]*)""",
              """"InstanceId":"({event_code}[^"]+)""",
        """"4":"({user}[^"]+)""",
        """"5":"({domain}[^"]+)""",
        """"6":"({logon_id}[^"]+)""",
        """"3":"({user_sid}[^"]+)""",
        """"2":"({target_user_sid}[^"]+)""",
        """"0":"({target_user}[^"]+)""",
        """"1":"({target_domain}[^"]+)"""
  ]
  DupFields = [ "host->dest_host" ]  
}
```