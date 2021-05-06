#### Parser Content
```Java
{
Name = beyondtrust-privileged-access-3
  Vendor = BeyondTrust
  Product = BeyondTrust PowerBroker
  Lms = Direct
  DataType = "privileged-access"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """EventName":"28693""","""EventTypeID":"28693""", """Category":"pbw""", """UserType":""" ]
  Fields = [
    """TimeCreated":"({time}\d+\/\d+\/\d\d\d\d\s\d+:\d+:\d+\s(am|AM|pm|PM))""",
    """exabeam_host=({host}[^\s]+)""",
    """EventName":"({event_code}\d+)"""",
    """AssetName":"({dest_host}[^"]+?)"""",
    """UserName":"({domain}[^\\\/]+?)[\\\/]+({user}[^"]+?)"""",
    """Path":"({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/"]+?))"""",
    """UserType":"({privileges}[^"]+?)"""",
    """RuleName":"(NONE|({event_name}[^"]+?))"""",
    ]
	DupFields = [ "directory->process_directory" ]
}
```