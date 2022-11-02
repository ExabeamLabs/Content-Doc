#### Parser Content
```Java
{
Name = lastpass-app-activity-1
  Vendor = LastPass
  Product = LastPass
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Action":""","""src-application-name":"LastPass Enterprise""","""src-endpoint":"EventReporting""","""src-account-name":"LastPass"""]
  Fields = [
    """"Time":"({time}\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})"""",
    """\d\d\dZ\s({host}[\w\-.]{1,2000})""",
    """"Username":"({user_email}[^@"]{1,2000}@[^"\.]{1,2000}\.[^"]{1,2000})"""",
    """"src-ip":"({src_ip}[a-fA-F\d:\.]{1,2000})"""",
    """"src-application-name"{1,20}:"{1,20}({app}[^"]{1,2000})""",
    """"application-action":"({activity}[^"]{1,2000})""",
    """"event-name":"({event_name}[^"]{1,2000})""""
  ]


}
```