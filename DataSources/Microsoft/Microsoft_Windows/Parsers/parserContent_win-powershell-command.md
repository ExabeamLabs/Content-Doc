#### Parser Content
```Java
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
      """Script Name =\s{1,100}({process}({directory}([\w:]+\\)?([^\\]+?\\)*?)({process_name}[^\\]*?))\s{1,100}Command Path =""",
      """User = (({domain}[^\\]+?)\\)?({user}[^\s]+)\s{1,100}Connected User =""",
      """CommandInvocation\(.+?\):\s{0,100}"({command_invocation}[^"]+)""",
      """value="{0,20}(?:function\s)?({command_module}[^\s"]+)""",
    """Host\s{0,100}Application\s{0,100}=\s{0,100}({powershell_image}[^\s]+)\s{1,100}EngineVersion""",
    """Host\s{0,100}Application\s{0,100}=\s{0,100}({command_line}[^\s]+)""""
    """CommandInvocation\(.+?\):\s{0,100}\\*"({command_invocation}[^"\\]+)""",
    """Details:.+?CommandInvocation.+?ParameterBinding.+?value=\\"(function\s)?({command_module}[^\s\\,"]+)""",
   ]
   DupFields = ["directory->process_directory"]
 }
```