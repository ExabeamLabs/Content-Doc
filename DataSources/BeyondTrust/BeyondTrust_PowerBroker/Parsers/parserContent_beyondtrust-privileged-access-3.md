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
    """TimeCreated":"({time}\d{1,100}\/\d{1,100}\/\d\d\d\d\s\d{1,100}:\d{1,100}:\d{1,100}\s(am|AM|pm|PM))""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """EventName":"({event_code}\d{1,100})"""",
    """AssetName":"({dest_host}[^"]{1,2000}?)"""",
    """UserName":"({domain}[^\\\/]{1,2000}?)[\\\/]{1,2000}({user}[^"]{1,2000}?)"""",
    """Path":"({process}({directory}(?:[^"]{1,2000})?[\\\/])?({process_name}[^\\\/"]{1,2000}?))"""",
    """UserType":"({privileges}[^"]{1,2000}?)"""",
    """RuleName":"(NONE|({event_name}[^"]{1,2000}?))"""",
    ]
	DupFields = [ "directory->process_directory" ]
}
```