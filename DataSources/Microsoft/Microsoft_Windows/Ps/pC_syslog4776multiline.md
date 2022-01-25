#### Parser Content
```Java
{
Name = syslog-4776-multiline
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Syslog
    DataType = "windows-4776"
    TimeFormat = "MM/dd/yyyy HH:mm:ss a"
	Conditions = ["""EventCode=4776""", """The computer attempted to validate the credentials""", """ComputerName =""", """Authentication Package"""]
	Fields =[
      """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d \w+)[^=]{1,2000}?LogName =""",
      """({event_code}4776)""",
      """ComputerName =({host}[\w\-\.]{1,2000})""",
      """Message=({event_name}[^<=]{1,2000}?)\s{0,100}<""",
      """The ({login_type}computer|domain)(\s\w+)? attempted to validate the credentials""",
      """Error Code:\s{0,100}({result_code}[^\s"]{1,2000})\s{0,100}"?""",
      """Source Workstation:\s{0,100}({dest_host}[^\s\<]{1,2000})\s{0,100}(<14>)?""",
      """Logon Account:\s{0,100}(({user_email}[^<:@]{1,2000}@[^\.]{1,2000}\.[^<:]{1,2000})|({user}[^:<]{1,200}?))\s{0,100}(<14>)?Source Workstation:""",
     ]


}
```