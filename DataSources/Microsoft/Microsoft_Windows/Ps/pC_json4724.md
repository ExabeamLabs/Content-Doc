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
        """"MachineName":"({host}[^."]{1,2000})""",
              """"TimeGenerated":"({time}[^"]{0,2000})""",
              """"InstanceId":"({event_code}[^"]{1,2000})""",
        """"4":"({user}[^"]{1,2000})""",
        """"5":"({domain}[^"]{1,2000})""",
        """"6":"({logon_id}[^"]{1,2000})""",
        """"3":"({user_sid}[^"]{1,2000})""",
        """"2":"({target_user_sid}[^"]{1,2000})""",
        """"0":"({target_user}[^"]{1,2000})""",
        """"1":"({target_domain}[^"]{1,2000})"""
  ]
  DupFields = [ "host->dest_host" ]  


}
```