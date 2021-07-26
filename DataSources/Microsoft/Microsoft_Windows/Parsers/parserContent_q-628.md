#### Parser Content
```Java
{
Name = q-628
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = QRadar
    DataType = "windows-password-reset"
    TimeFormat = "epoch_sec"
    Conditions = [ "EventIDCode=628" ]
    Fields = [
      """({event_name}User Account password set)""",
      """TimeGenerated=({time}\d{1,100})""",
      """Computer=({host}[^\s]{1,2000})""",
      """EventID=({event_code}\d{1,100})""",
      """Target Account Name:\s{1,100}({target_user}.+?)\s{1,100}Target Domain:\s{1,100}({target_domain}.+?)\s{1,100}Target Account ID:\s{0,100}({target_user_sid}.+?)\s{1,100}Caller User""",
      """Caller User Name:\s{1,100}(?=\w)({user}.+?)\s{1,100}Caller Domain:\s{1,100}(?=\w)({domain}.+?)\s{1,100}Caller Logon ID:\s{1,100}\([^,]{1,2000}
```