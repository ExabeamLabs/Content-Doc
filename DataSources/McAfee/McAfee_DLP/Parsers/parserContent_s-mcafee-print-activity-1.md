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
     """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100}), IncidentId""",
     """\sApplicationProductName="{0,20}({app}[^"]+)""",
     """\sTotalContentSize="{0,20}({bytes}\d{1,100})""",
     """\sIP="{0,20}({dest_ip}[a-fA-F:\d.]+)""",
     """\sRulesToDisplay="{0,20}({event_name}[^"]+)""",
     """\sName="{0,20}({host}[^"]+)""",
     """\sFileName="{0,20}({object}[^"]+)""",
     """\sdestination="{0,20}({printer_name}[^"]+)""",
     """\sUsername_NTLM="{0,20}(({domain}[^\\]+)\\*)?({user}[^"]+)"""
  ]
}
```