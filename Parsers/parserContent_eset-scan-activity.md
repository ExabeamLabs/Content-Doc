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
  """({time}\d+-\d+-\d+ \d+:\d+:\d+)""",
  """Scan ID:\s*({scan_id}\d+)""",
  """Computer:\s*({host}[^,]+)""",
  """IP Address:\s*({src_ip}[^,]+)""",
  """Server Name:\s*({dest_host}[^.\s,]+)""",
  """User1:\s*(SYSTEM|({user}[^,]+))""",
  """Group Name:\s({group}[^,]+)""",
  """Domain Name:\s*({domain}[^,]+)"""
  ]
}
```