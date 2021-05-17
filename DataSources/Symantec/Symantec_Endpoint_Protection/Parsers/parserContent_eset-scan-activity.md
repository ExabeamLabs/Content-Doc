#### Parser Content
```Java
{
Name = eset-scan-activity
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Scan ID:""" , """End Time:""", """Computer:""", """Domain Name:""", """User1:"""]
  Fields =[
  """({time}\d{1,100}-\d{1,100}-\d{1,100} \d{1,100}:\d{1,100}:\d{1,100})""",
  """Scan ID:\s{0,100}({scan_id}\d{1,100})""",
  """Computer:\s{0,100}({host}[^,]{1,2000})""",
  """IP Address:\s{0,100}({src_ip}[^,]{1,2000})""",
  """Server Name:\s{0,100}({dest_host}[^.\s,]{1,2000})""",
  """User1:\s{0,100}(SYSTEM|({user}[^,]{1,2000}))""",
  """Group Name:\s({group}[^,]{1,2000})""",
  """Domain Name:\s{0,100}({domain}[^,]{1,2000})"""
  ]
}
```