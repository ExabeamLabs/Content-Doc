#### Parser Content
```Java
{
Name = quest-change-member-added-1
     DataType = "member-added"
     Conditions = [ """CEF:""", """Quest Software""", """|Change Auditor|""", """|Active Directory|""", """Member added to group""" ]
     Fields = ${QuestParserTemplates.quest-change-auditor-events.Fields}[
       """msg=[^\\]{1,2000}\\*({account_id}[^(]{1,2000})[^=]{1,2000}?was added to group\s[^\\]{1,2000}\\*({group_name}\S+)\s"""
]
}
quest-change-auditor-events = {
    Vendor = Quest Software
    Product = Change Auditor
    Lms = Splunk
    TimeFormat = "MMM dd yyyy HH:mm:ss"
    Fields = [
      """start=({time}\w+\s\d\d\s\d\d\d\d\s\d\d:\d\d:\d\d)""",
      """dvchost=({host}[\w\-.]{1,2000})""",
      """domain=({domain}\S+)""",
      """categoryOutcome=({outcome}\S+)""",
      """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """userMail=({user_email}[^@=]{1,2000}@[^\.]{1,2000}[^\s]{1,2000})""",
      """suid=({user_sid}\S+)""",
      """suser=(({domain}[^\\]{1,2000})\\*)?({user}[^=]{1,2000}?)\s\w+=""",
      """event=({event_name}[^=]{1,2000}?)\s\w+=""",
      """msg=({additional_info}[^=]{1,2000}?)\s{0,100}\w+="""
    ]
 
```