#### Parser Content
```Java
{
Name = avecto-local-logon
    Vendor = BeyondTrust
    Product = BeyondTrust Privilege Management
    Lms = Splunk
    DataType = "local-logon"
    TimeFormat = "MM/dd/yyyy HH:mm:ss a"
    Conditions = [ """SourceName=Avecto Defendpoint Service""", """Message=Detected user logon"""]
    Fields = [
      """exabeam_raw=({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (am|AM|pm|PM))""",
      """ComputerName=({host}[^\s]{1,2000})""",
      """Message=({activity_type}.+?)\s{1,100}Command Line:""",
      """User Name:\s{0,100}(?:[A-F\d\-]{36}|({user}.+?))\s{1,100}User Domain SID:""",
      """User Domain Name:\s{0,100}({domain}.*?)\s{1,100}User Domain Name""",
      """User SID:\s{0,100}({user_sid}.*?)\s{1,100}User Name""",
      """Administrator:\s{0,100}({admin}.*?)\s{1,100}Power User""",
      """Power User:\s{0,100}({power_user}.*?)\s{1,100}Workstyle""",
      """Workstyle:\s{0,100}({account_info}.*?)\s{1,100}Workstyle""",
      """IP4 Addresses:\s{0,100}[^,]{1,2000}
```