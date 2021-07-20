#### Parser Content
```Java
{
Name = q-member-removed-2003
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = QRadar
  DataType = "windows-member-removed"
  TimeFormat = "epoch_sec"
  Conditions = [ "Security Enabled", " Group Member Removed" ]
  Fields = [
    """({event_name}Security Enabled [\w\s]{1,2000} Group Member Removed)""",
    """EventID=({event_code}\d{1,100})""",
    """TimeGenerated=({time}\d{1,100})""",
    """Computer=({host}[^\s]{1,2000})""",
    """Security Enabled ({group_type}[^\s]{1,2000}) Group Member""",
    """Group Member.+?Member ID:\s{1,100}(%\{)?({account_id}(?=[^\\]{1,2000}\\)({sid_domain}[^\\]{1,2000})\\({sid_user}[^\s]{1,2000})|(?:[^\s}]{1,2000})).+Target Account Name:\s{1,100}({group_name}.+?)\s{1,100}Target Domain:\s{1,100}({group_domain}[^\s]{1,2000}).+?Target Account ID:\s{1,100}%\{({group_id}[\w\-]{1,2000}).+Caller User Name:\s{1,100}({user}.+?)\s{1,100}Caller Domain:\s{1,100}({domain}.+?)\s{1,100}Caller Logon ID:\s{1,100}\([^,]{1,2000}
```