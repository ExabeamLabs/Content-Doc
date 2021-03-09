#### Parser Content
```Java
{
Name = s-mcafee-print-activity-1
  Vendor = McAfee
  Product = McAfee DLP
  Lms = Splunk
  DataType = "print-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """IncidentType="""", """ViolationLocalTime="""", """RulesToDisplay=""", """Printing""", """FileName=""", """ShortMatchString=""" ]  
  Fields = [
     """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+), IncidentId""",
     """\sApplicationProductName="*({app}[^"]+)""",
     """\sTotalContentSize="*({bytes}\d+)""",
     """\sIP="*({dest_ip}[a-fA-F:\d.]+)""",
     """\sRulesToDisplay="*({event_name}[^"]+)""",
     """\sName="*({host}[^"]+)""",
     """\sFileName="*({object}[^"]+)""",
     """\sdestination="*({printer_name}[^"]+)""",
     """\sUsername_NTLM="*(({domain}[^\\]+)\\*)?({user}[^"]+)"""
  ]
}
```