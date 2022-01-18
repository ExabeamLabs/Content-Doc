#### Parser Content
```Java
{
Name = s-mcafee-print-activity-1
  Vendor = McAfee
  Product = McAfee DLP
  Lms = Splunk
  DataType = "print-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """IncidentType="""", """ViolationLocalTime="""", """RulesToDisplay=""", """Printing""", """FileName =""", """ShortMatchString=""" ]  
  Fields = [
     """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100}), IncidentId""",
     """\sApplicationProductName ="{0,20}({app}[^"]{1,2000})""",
     """\sTotalContentSize="{0,20}({bytes}\d{1,100})""",
     """\sIP="{0,20}({dest_ip}[a-fA-F:\d.]{1,2000})""",
     """\sRulesToDisplay="{0,20}({event_name}[^"]{1,2000})""",
     """\sName ="{0,20}({host}[^"]{1,2000})""",
     """\sFileName ="{0,20}({object}[^"]{1,2000})""",
     """\sdestination="{0,20}({printer_name}[^"]{1,2000})""",
     """\sUsername_NTLM="{0,20}(({domain}[^\\]{1,2000})\\*)?({user}[^"]{1,2000})"""
  ]


}
```