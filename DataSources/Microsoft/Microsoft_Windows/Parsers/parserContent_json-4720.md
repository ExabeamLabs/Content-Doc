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
	      """"MachineName":"({host}[^."]{1,2000})""",
              """"TimeGenerated":"({time}[^"]{0,2000})""",
              """"InstanceId":"({event_code}[^"]{1,2000})""",
	      """"4":"({user}[^"]{1,2000})""",
	      """"5":"({domain}[^"]{1,2000})""",
	      """"6":"({logon_id}[^"]{1,2000})""",
	      """"2":"({account_id}[^"]{1,2000})""",
	      """"0":"({account_name}[^"]{1,2000})""",
	      """"1":"({account_domain}[^"]{1,2000})"""
  ]
  DupFields = ["host->dest_host"]
}
```