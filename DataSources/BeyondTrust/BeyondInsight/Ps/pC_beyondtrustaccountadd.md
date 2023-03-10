#### Parser Content
```Java
{
Name = beyondtrust-account-add
  Vendor = BeyondTrust
  Product = BeyondInsight
  Lms = Direct
  DataType = "account-creation"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """CEF:""", """|PBPS|RequestorApprover|""", """|BeyondTrust|BeyondInsight|""", """BeyondTrustBeyondInsightOperation=Add""" ]
  Fields = [
  """start=({time}\w{3,4}\s\d{1,2}\s\d{4}\s\d{1,2}:\d{1,2}:\d{1,2})"""
  """src=({src_ip}[A-fa-f\d:.]{1,2000})"""
  """suser=({user}[^\s]{1,2000})"""
  """BeyondTrustBeyondInsightOperation=({activity}[^\s]{1,2000})"""
  """dst=({dest_ip}[A-fa-f\d:.]{1,2000})"""
  """\w+\s\d{1,2}\s\d{1,2}:\d{1,2}:\d{1,2}\s({host}[\w\-.]{1,2000})"""
  """BeyondTrustBeyondInsightEventSeverity=({severity}[^\s]{1,2000})"""
  """({app}BeyondInsight)"""
  """dhost=({account_domain}[^\/,]{1,2000}?)[\/]{1,100}({account_name}[^,\s]{1,2000})"""
  ]


}
```