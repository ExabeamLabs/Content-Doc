#### Parser Content
```Java
{
Name = raw-627
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-password-change"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = [ "Change Password Attempt:"]
    Fields = [ 
      """({event_name}Change Password Attempt)""",
      """({time}\w+ \d{1,2} [\d:]{1,2000} \d{1,100})""",
      """Security,({record_id}\d{1,100})""",
      """\sType=({outcome}.+?)\s{1,100}\w+=""",
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)(,|\s)({host}[\w\-.]{1,2000})""",
      """({host}[\w\-.]{1,2000})\/Security""",
      """Computer=({host}[\w\-.]{1,2000})""",
      """\s{1,100}({outcome}(?i)((audit|success|failure)( |_)(success|audit|failure)))\s{1,100}""",
      """({event_code}627)""",
      """Target Account Name\s{0,100}:\s{0,100}(?=\w)({target_user}.+?)\s{1,100}Target Domain\s{0,100}:\s{0,100}(?=\w)({target_domain}.+?)\s{1,100}Target Account ID\s{0,100}:\s{0,100}\%\{({target_user_sid}[^}]{1,2000})\}""",
      """Caller User Name:\s{1,100}({user}.+?)\s{1,100}Caller Domain:\s{1,100}({domain}.+?)\s{1,100}Caller Logon ID:\s{1,100}\([^,]{1,2000}
```