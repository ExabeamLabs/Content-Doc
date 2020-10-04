#### Parser Content
```Java
{
Name = powershell-800-syslog
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "powershell-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """Windows PowerShell""", """PowerShell (800)""", """CommandLine=""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)[+-]\S+\s*({host}\S+)\sEvntSLog""",
    """UserId=({domain}.*?)\\+(SYSTEM|({user}.*?))\s+HostName""",
    """Host\s*Application\s*=\s*({powershell_image}[^=]+\.\w+)\s""",
    """ScriptName=\s*({process}({directory}([\w:]+\\)?([^\\=]+?\\)*?)({process_name}[^\\=]*?))\s+CommandLine=""",
    """CommandLine=\s*({command_line}.*?)\s*Details:""",
    """Details:.*?CommandInvocation.*?ParameterBinding.*?value="+\s*({command_module}[^"]*?)\s*"+""",
    """Details:.+?CommandInvocation\(.+?\):\s*\\*"+\s*({command_invocation}[^"\\]+)\s*""",
    """({event_code}800)"""
  ]
}

 {
   Name = win-powershell-command
   Vendor = Microsoft
   Product = Microsoft Windows
   Lms = Direct
   DataType = "process-created"
   TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
   Conditions = [  """>4103</EventID>""",   """CommandInvocation""",       """Script Name ="""    ]
   Fields = [
      """exabeam_host=({host}[\w\-.]+)""",
      """<TimeCreated SystemTime=\'({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{9}Z)\'\/>""",
      """>({event_code}4103)<\/EventID>""",
      """<Computer>({dest_host}.*?)<\/Computer>""",
      """<Security UserID='({user_sid}[\w-]+)'""",
      """Script Name =\s+({process}({directory}([\w:]+\\)?([^\\]+?\\)*?)({process_name}[^\\]*?))\s+Command Path =""",
      """User = (({domain}[^\\]+?)\\)?({user}[^\s]+)\s+Connected User =""",
      """CommandInvocation\(.+?\):\s*"({command_invocation}[^"]+)""",
      """value="*(?:function\s)?({command_module}[^\s"]+)""",
    """Host\s*Application\s*=\s*({powershell_image}[^\s]+)\s+EngineVersion""",
    """Host\s*Application\s*=\s*({command_line}[^\s]+)""""
    """CommandInvocation\(.+?\):\s*\\*"({command_invocation}[^"\\]+)""",
    """Details:.+?CommandInvocation.+?ParameterBinding.+?value=\\"(function\s)?({command_module}[^\s\\,"]+)""",
   ]
 }

{
  Name = s-4740-1
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-account-lockout"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """EventCode=4740""", """EventType=""", """A user account was locked out""" ]
  Fields = [
    """({host}[\w\-.]+)\s+({time}\d+\/\d+\/\d+\s+\d+:\d+:\d+\s+(am|AM|pm|PM))""",
    """ComputerName=({dest_host}[\w\-.]+)""",
    """({event_code}4740)""",
    """({event_name}A user account was locked out)"""
    """RecordNumber=({record_id}[^;"]+)""",
    """Keywords=({outcome}[^;"]+)""",
    """Subject=.*?Account Name=({caller_user}[^;"\s]+)""",
    """Subject=.*?Account Domain=({caller_domain}[^;"\s]+)""",
    """Logon ID=({logon_id}[^;"\s]+)""",
    """Security ID=({user_sid}[^;"]+);Account Name=({user}[^;"\s]+);Additional Information=""",
    """Caller Computer Name=\\*({src_host}[\w\-.]+)""",
  ]
  DupFields=[ "caller_domain->domain" ]
}
```