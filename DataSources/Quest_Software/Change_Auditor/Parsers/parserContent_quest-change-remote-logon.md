#### Parser Content
```Java
{
Name = quest-change-remote-logon
     DataType = "remote-logon"
     Conditions = [ """CEF:""", """Quest Software""", """|Change Auditor|""", """|Logon Activity|""", """User logged on interactively from a remote computer""", """logonType=10"""  ]
     Fields = ${QuestParserTemplates.quest-change-auditor-events.Fields}[
       """logonType=({logon_type}\d+)"""
]	   
}
quest-change-auditor-events = {
    Vendor = Quest Software
    Product = Change Auditor
    Lms = Splunk
    TimeFormat = "MMM dd yyyy HH:mm:ss"
    Fields = [
      """start=({time}\w+\s\d\d\s\d\d\d\d\s\d\d:\d\d:\d\d)""",
      """dvchost=({host}[\w\-.]+)""",
      """domain=({domain}\S+)""",
      """categoryOutcome=({outcome}\S+)""",
      """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """userMail=({user_email}[^@=]+@[^\.]+[^\s]+)""",
      """suid=({user_sid}\S+)""",
      """suser=(({domain}[^\\]+)\\*)?({user}[^=]+?)\s\w+=""",
      """event=({event_name}[^=]+?)\s\w+=""",
      """msg=({additional_info}[^=]+?)\s*\w+="""
    ]

```