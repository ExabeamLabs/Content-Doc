#### Parser Content
```Java
{
Name = quest-member-removed-1
     DataType = "member-removed"
     Conditions = [ """ChangeAuditor""", """|Active Directory|""", """|User member-of removed|"""  ]

quest-auditor-events = {
    Vendor = Quest Software
    Product = Change Auditor
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
    Fields = [
      """\|({time}\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\|""",
      """\w{3}\s{1,100}\d{1,2}\s{1,100}\d\d:\d\d:\d\d\s{1,100}({host}[\w\-.]{1,2000})\s""",
      """ChangeAuditor[^\|]{1,2000}\|{1,20}(?:[^\|]{1,2000}\|{1,20}){1}({object}[^\|]{1,2000})\|{1,20}(?:[^\|]{1,2000}\|{1,20}){3}(({domain}[^\\\|]{1,2000}?)\\{1,25})?({user}\S{1,2000}?)\|{1,20}({user_sid}[^\|]{1,2000}?)\|{1,20}(({target_domain}[^\\\|]{1,2000}?)\\{1,25})?({target_user}\S{1,2000}?)\|{1,20}({event_name}[^\|]{1,2000}?)\|{1,20}({src_host}[^\|]{1,2000}?)\|{1,20}({additional_info}[^\|]{1,2000})\|{1,20}(?:[^\|]{1,2000}\|{1,20}){12}({app}[^\|]{1,2000})\|{1,20}({outcome}[^\|"]{1,2000}?)(\\n)?(\||"|$| )"""
    ]
    DupFields = [ "event_name->activity" 
}
```