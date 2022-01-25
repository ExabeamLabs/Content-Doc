#### Parser Content
```Java
{
Name = s-salesforce-app-login
  Vendor =  Salesforce
  Product = Salesforce
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """LoginGeoId=""","""|Quicklook_ID__c=""" ]
  Fields = [
    """\|Name ="({user}[^"]{1,2000})"""",
    """\|LoginTime="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\|SourceIp="({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\|LoginUrl="({dest_host}[^"]{1,2000})"""",
    """\|Browser="({browser}[^"]{1,2000})"""",
    """\|Platform="({os}[^"]{1,2000})"""",
    """\|Status="({outcome}[^"]{1,2000})"""",
    """\|Application="({app}[^"]{1,2000})"""",
  ]
  DupFields = [ "outcome->failure_reason" ]


}
```