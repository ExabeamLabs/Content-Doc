#### Parser Content
```Java
{
Name = raw-628
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct 
    DataType = "windows-password-reset"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = [ "User Account password set:"]
    Fields = [
      """({event_name}User Account password set)""",
      """({time}\w+ \d{1,2} [\d:]{1,2000} \d{1,100})""",
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """(?i)(information)(,|\s{1,100})({host}[\w.\-]{1,2000})""",
      """(?i)((audit|success|failure)( |_)(success|audit|failure))\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}Account Management""",
      """({host}[^\/\s]{1,2000})\/Security""",
      """ComputerName =({host}[\w.\-]{1,2000})""",
      """({event_code}628)""",
      """Target Account Name:\s{1,100}({target_user}.+?)\s{1,100}Target Domain:\s{1,100}({target_domain}.+?)\s{1,100}Target Account ID:\s\%\{({target_user_sid}[^}]{1,2000})\}""",
      """Caller User Name:\s{1,100}(?=\w)({user}.+?)\s{1,100}Caller Domain:\s{1,100}(?=\w)({domain}.+?)\s{1,100}Caller Logon ID:\s{1,100}\([^,]{1,2000

}
```