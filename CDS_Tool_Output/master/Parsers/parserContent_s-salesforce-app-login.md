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
    """\|Name="({user}[^"]+)"""",
    """\|LoginTime="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\|SourceIp="({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\|LoginUrl="({dest_host}[^"]+)"""",
    """\|Browser="({browser}[^"]+)"""",
    """\|Platform="({os}[^"]+)"""",
    """\|Status="({outcome}[^"]+)"""",
    """\|Application="({app}[^"]+)"""",
  ]
  DupFields = [ "outcome->failure_reason" ]
}
```