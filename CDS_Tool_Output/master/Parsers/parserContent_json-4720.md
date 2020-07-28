#### Parser Content
```Java
{
Name = json-4720
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-account-created"
  TimeFormat = "MM/dd/yyyy H:mm:ss a"
  Conditions = [ """"InstanceId":"4720"""" ]
  Fields = [
    """({event_name}A user account was created)""",
	      """"MachineName":"({host}[^."]+)""",
              """"TimeGenerated":"({time}[^"]*)""",
              """"InstanceId":"({event_code}[^"]+)""",
	      """"4":"({user}[^"]+)""",
	      """"5":"({domain}[^"]+)""",
	      """"6":"({logon_id}[^"]+)""",
	      """"2":"({account_id}[^"]+)""",
	      """"0":"({account_name}[^"]+)""",
	      """"1":"({account_domain}[^"]+)"""
  ]
  DupFields = ["host->dest_host"]
}
```