#### Parser Content
```Java
{
Name = s-member-added-2003
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-member-added"
  TimeFormat = "MM/dd/yyyy hh:mm:ss a"
  Conditions = [ """LogName =""", """SourceName =""", "Group Member Added:", "Security Enabled", "EventCode=" ]
  Fields = [
    """({event_name}Security Enabled [\w\s]{1,2000} Group Member Added)""",
    """exabeam_raw=({time}\d\d/\d\d/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))""",
    """ComputerName =({host}[\w.\-]{1,2000})""",
    """EventCode=({event_code}\w+)""",
    """Security Enabled ({group_type}[^\s]{1,2000}) Group Member""",
    """Group Member.+?Member ID:\s{1,100}({account_id}(?=[^\\]{1,2000}\\)({sid_domain}[^\\]{1,2000})\\({sid_user}.+?)|(?:.+?))\s{1,100}Target Account""",
    """Target Account Name:\s{1,100}({group_name}.+?)\s{1,100}Target""",
    """Target Domain:\s{1,100}({group_domain}[^\s]{1,2000})""",
    """Target Account ID:\s{1,100}({group_id}.+?)\s{1,100}Caller""",
    """Caller User Name:\s{1,100}({user}.+?)\s{1,100}Caller""",
    """Caller Domain:\s{1,100}({domain}.+?)\s{1,100}Caller""",
    """Caller Logon ID:\s{1,100}\([^,]{1,2000

}
```