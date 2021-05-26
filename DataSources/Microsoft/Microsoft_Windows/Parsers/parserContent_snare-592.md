#### Parser Content
```Java
{
Name = snare-592
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-process-created"
    IsHVF = true
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = ["""A new process has been created:""", """Detailed Tracking""", "\t592\t" ]
    Fields = [ """exabeam_host=({host}[^\s]{1,2000})""",
      """({event_name}A new process has been created)""",
      """Security\s{0,100}\d{1,100}\s{1,100}(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \d{1,100})""",
      """({event_code}592)""",
      """(Information|Audit Success|Success Audit)\s{1,100}({host}[^\s]{1,2000})""",
      """Image File Name:\s{1,100}({process}({directory}(?:[^"]{1,2000})?[\\\/])?({process_name}[^\\\/"]{1,2000}?))\s{1,100}Creator Process ID:""",
      """Image File Name:\s{1,100}({path}.+?)\s{1,100}Creator Process ID:""",
      """User Name:\s{1,100}({user}.+?)\s{1,100}Domain:\s{1,100}({domain}.+?)\s{1,100}Logon ID:\s{1,100}\([^,]{1,2000}
```